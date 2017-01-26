/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 * Author: Matias Fontanini <matias.fontanini@gmail.com>
 * 
 * This small application decrypts WEP/WPA2(AES and TKIP) traffic on
 * the fly and writes the result into a tap interface. 
 * 
 */

// libtins
#include <tins/tins.h>
// linux/POSIX stuff
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdio.h>
// STL
#include <iostream>
#include <atomic>
#include <algorithm>
#include <tuple>
#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <functional>
#include <memory>
#include <sstream>
#include <chrono>
#include "tins/packet_writer.h"
//Boost
#include <boost/program_options.hpp>

using namespace Tins;

using std::hex;
using std::atomic;
using std::lock_guard;
using std::mutex;
using std::unique_ptr;
using std::unique_lock;
using std::condition_variable;
using std::move;
using std::memset;
using std::bind;
using std::cout;
using std::endl;
using std::runtime_error;
using std::invalid_argument;
using std::exception;
using std::thread;
using std::swap;
using std::tuple;
using std::make_tuple;
using std::string;
using std::queue;
using std::get;
using std::vector;
using Tins::pdu_not_found;
using Tins::PacketWriter;
// our running flag
atomic<bool> running;
atomic<bool> decrypt_running;

// unique_fd - just a wrapper over a file descriptor which closes
// the fd in its dtor. non-copyable but movable

class unique_fd {
public:
    static constexpr int invalid_fd = -1;

    unique_fd(int fd = invalid_fd)
    : fd_(fd) {

    }


    unique_fd(unique_fd &&rhs)
    : fd_(invalid_fd) {
        *this = move(rhs);
    }

    unique_fd& operator=(unique_fd&& rhs) {
        if (fd_ != invalid_fd) {
            ::close(fd_);
        }
        fd_ = invalid_fd;
        swap(fd_, rhs.fd_);
        return *this;
    }

    ~unique_fd() {
        if (fd_ != invalid_fd) {
            ::close(fd_);
        }
    }

    unique_fd(const unique_fd&) = delete;
    unique_fd& operator=(const unique_fd&) = delete;

    int operator*() {
        return fd_;
    }

    operator bool() const {
        return fd_ != invalid_fd;
    }
private:
    int fd_;
};

// packet_buffer - buffers packets, decrypts them and flushes them into 
// the interface using an auxiliary thread.

class packet_buffer {
public:
    typedef unique_ptr<PDU> unique_pdu;

    packet_buffer(PacketWriter writer, Crypto::WPA2Decrypter wpa2d,
                  Crypto::WEPDecrypter wepd, bool save_decrypted_only)
    : writer_(move(writer)), wpa2_decrypter_(move(wpa2d)), wep_decrypter_(move(wepd)) {
        save_decrypted_pkts_only_ = save_decrypted_only;
        // Requires libtins 3.4
        #ifdef TINS_HAVE_WPA2_CALLBACKS
        using namespace std::placeholders;
        wpa2_decrypter_.ap_found_callback(bind(&packet_buffer::on_ap_found, this, _1, _2));
        wpa2_decrypter_.handshake_captured_callback(bind(&packet_buffer::on_handshake_captured,
                                                         this, _1, _2, _3));
        #endif // TINS_HAVE_WPA2_CALLBACKS
    }

    packet_buffer(const packet_buffer&) = delete;
    packet_buffer& operator=(const packet_buffer&) = delete;

    ~packet_buffer() {
	if (thread_.joinable())
    	    thread_.join();
        //thread_.join();
    }

    void add_packet(unique_pdu pkt) {
        lock_guard<mutex> _(mtx_);
        packet_queue_.push(move(pkt));
        cond_.notify_one();
    }

    void stop_running() {
        lock_guard<mutex> _(mtx_);
        cond_.notify_one();
    }

    void wait_for_thread() {
    	thread_.join();
    }

    void run() {
        thread_ = thread(&packet_buffer::thread_proc, this);
    }

    void change_output_file(const string &new_output_file) {
      	writer_.change_output_file(new_output_file);
    }

private:
    typedef HWAddress<6> address_type;

    EthernetII make_eth_packet(Dot11Data &dot11) {
        if (dot11.from_ds() && !dot11.to_ds()) {
            return EthernetII(dot11.addr1(), dot11.addr3());
        }
        else if (!dot11.from_ds() && dot11.to_ds()) {
            return EthernetII(dot11.addr3(), dot11.addr2());
        }
        else {
            return EthernetII(dot11.addr1(), dot11.addr2());
        }
    }

    void on_ap_found(const string& ssid, const address_type& bssid) {
        cout << "AP found: " << ssid << ": " << bssid << endl;
    }

    void on_handshake_captured(const string& ssid, const address_type& bssid,
                               const address_type& client_hw) {
        cout << "Captured handshake for " << ssid << " (" << bssid << "): " << client_hw << endl;
    }

    template<typename Decrypter>
    bool try_decrypt(Decrypter &decrypter, PDU &pdu) {
        if (!writer_.is_handle_set()) {
          cout << "Writer not set, so returning\n";
          return false;
        }
        if (decrypter.decrypt(pdu)) {
            auto buffer = pdu.serialize();
	          writer_.write(pdu);
            return true;
        } else if (!save_decrypted_pkts_only_) {
	         //Unable to decrypt, still write
	         writer_.write(pdu);
        }
        return false;
    }

    void thread_proc() {
        while (decrypt_running) {
            unique_pdu pkt;
            // critical section
            {
                unique_lock<mutex> lock(mtx_);
                if (!decrypt_running) {
                    return;
                }
                if (packet_queue_.empty()) {
                    cond_.wait(lock);
                    // if it's still empty, then we're done
                    if (packet_queue_.empty()) {
                        return;
                    }
                }
                pkt = move(packet_queue_.front());
                packet_queue_.pop();
            }
            // non-critical section
            if (!try_decrypt(wpa2_decrypter_, *pkt.get())) {
                try_decrypt(wep_decrypter_, *pkt.get());
            }
        }
    }

    unique_fd fd_;
    thread thread_;
    mutex mtx_;
    condition_variable cond_;
    queue<unique_pdu> packet_queue_;
    PacketWriter writer_;
    Crypto::WPA2Decrypter wpa2_decrypter_;
    Crypto::WEPDecrypter wep_decrypter_;
    bool save_decrypted_pkts_only_;
};


// traffic_decrypter - decrypts the traffic and forwards it into a
// bufferer

class traffic_decrypter {
public:
    traffic_decrypter(PacketWriter writer, Crypto::WPA2Decrypter wpa2d,
                      Crypto::WEPDecrypter wepd, bool save_decrypted_only)
    : bufferer_(move(writer), move(wpa2d), move(wepd), save_decrypted_only) {
    }

    void decrypt_traffic(Sniffer &sniffer) {
        using std::placeholders::_1;
        bufferer_.run();
        sniffer.sniff_loop(bind(&traffic_decrypter::callback, this, _1), 0, 300);
        bufferer_.stop_running();
    }

    void decrypt_traffic_continuous(Sniffer &sniffer, const string &output_file_prefix,
      const string &output_dir, int total_capture_time, int capture_time_per_file) {
        std::chrono::time_point<std::chrono::system_clock> start, current;
        start = std::chrono::system_clock::now();
        int file_num = 0;
        while (running) {
          ++file_num;
          const string output_file = output_dir + "/" + output_file_prefix + std::to_string(file_num) + ".pcap";
          cout << "Writing to file:" << output_file << endl;
          using std::placeholders::_1;
          bufferer_.change_output_file(output_file);
          decrypt_running = true;
          bufferer_.run();
          sniffer.sniff_loop(bind(&traffic_decrypter::callback, this, _1), 0, capture_time_per_file);
          bufferer_.stop_running();
          decrypt_running = false;
          bufferer_.wait_for_thread();
          cout << "Done writing\n";
          if (total_capture_time > 0) {
            current = std::chrono::system_clock::now();
            std::chrono::duration<double> elapsed_seconds = current - start;
            //cout << "epapsed sec: " << elapsed_seconds.count() << " max_sec: " << max_time_secs << endl;
            if ((uint32_t)elapsed_seconds.count() > total_capture_time) {
              break;
            }
          }
        }
        cout << "Done with the while loop in decrypt_traffic_continuous\n";
    }


private:
    bool callback(PDU &pdu) {
        if (pdu.find_pdu<Dot11>() == nullptr && pdu.find_pdu<RadioTap>() == nullptr) {
            throw runtime_error("Expected an 802.11 interface in monitor mode");
        }
        bufferer_.add_packet(packet_buffer::unique_pdu(pdu.clone()));
        return decrypt_running;
    }

    packet_buffer bufferer_;
    bool save_decrypted_pkts_only_;
};


// if_up - brings the interface up

void if_up(const char *name) {
    int err, fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ);
    if ((err = ioctl(fd, SIOCGIFFLAGS, (void *) &ifr)) < 0) {
        close(fd);
        cout << strerror(errno) << endl;
        throw runtime_error("Failed get flags");
    }
    ifr.ifr_flags |= IFF_UP|IFF_RUNNING;
    if ((err = ioctl(fd, SIOCSIFFLAGS, (void *) &ifr)) < 0) {
        close(fd);
        cout << strerror(errno) << endl;
        throw runtime_error("Failed to bring the interface up");
    }
}

// create_tap_dev - creates a tap device

tuple<unique_fd, string> create_tap_dev() {
    struct ifreq ifr;
    int err;
    char clonedev[] = "/dev/net/tun";
    unique_fd fd = open(clonedev, O_RDWR);

    if (!fd) {
        throw runtime_error("Failed to open /dev/net/tun");
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;   

    if ((err = ioctl(*fd, TUNSETIFF, (void *) &ifr)) < 0) {
        throw runtime_error("Failed to create tap device");
    }

    return make_tuple(move(fd), ifr.ifr_name);
}

// sig_handler - SIGINT handler, so we can release resources appropriately
void sig_handler(int) {
    if (running) {
        cout << "Stopping the sniffer...\n";
        running = false;
	      decrypt_running = false;
    }
}


typedef tuple<Crypto::WPA2Decrypter, Crypto::WEPDecrypter> decrypter_tuple;

// Creates a traffic_decrypter and puts it to work
void decrypt_traffic(const string &output_file, Sniffer &sniffer, decrypter_tuple tup) {
    PacketWriter writer(output_file, DataLinkType<RadioTap>());
    traffic_decrypter decrypter(
        move(writer),
        move(get<0>(tup)),
        move(get<1>(tup)),
        false
    );
    decrypter.decrypt_traffic(sniffer);
}

// Creates a traffic_decrypter and puts it to work
void continuous_decrypt(Sniffer &sniffer, PacketWriter &writer, decrypter_tuple tup, const string &output_file_prefix,
     const string &output_dir, int total_capture_time, int capture_time_per_file, bool save_decrypted_only) {
    traffic_decrypter decrypter(
	      move(writer),
        move(get<0>(tup)),
        move(get<1>(tup)),
        save_decrypted_only
    );
    decrypter.decrypt_traffic_continuous(sniffer, output_file_prefix,
      output_dir, total_capture_time, capture_time_per_file);
    cout << "Done with continuous decrypt\n";
}

// parses the arguments and returns a tuple (WPA2Decrypter, WEPDectyper)
// throws if arguments are invalid
decrypter_tuple parse_args(const vector<string> &args) {
    decrypter_tuple tup;
    for (const auto &i : args) {
        if (i.find("wpa:") == 0) {
            auto pos = i.find(':', 4);
            if (pos != string::npos) {
                get<0>(tup).add_ap_data(
                    i.substr(pos + 1), // psk
                    i.substr(4, pos - 4) // ssid
                );
            }
            else {
                throw invalid_argument("Invalid decryption data");
            }
        }
        else if (i.find("wep:") == 0) {
            const auto sz = string("00:00:00:00:00:00").size();
            if (sz + 4 >= i.size()) {
                throw invalid_argument("Invalid decryption data");
            }
            get<1>(tup).add_password(
                i.substr(5, sz), // bssid
                i.substr(5 + sz) // passphrase
            );
        }
        else {
            throw invalid_argument("Expected decription data.");
        }
    }
    return tup;
}


void print_usage(const char *arg0){
    cout << "Usage: " << arg0 << " <interface (monitor)> DECRYPTION_DATA [DECRYPTION_DATA] [...]\n\n";
    cout << "Where DECRYPTION_DATA can be: \n";
    cout << "\twpa:SSID:PSK - to specify WPA2(AES or TKIP) decryption data.\n";
    cout << "\twep:BSSID:KEY - to specify WEP decryption data.\n\n";
    cout << "Examples:\n";
    cout << "\t" << arg0 << " wlan0 wpa:MyAccessPoint:some_password\n";
    cout << "\t" << arg0 << " mon0 wep:00:01:02:03:04:05:blahbleehh\n";
    exit(1);
}

enum ArgParsingReturnValues {
  SUCCESS = 0;
  ERROR_IN_COMMAND_LINE = 1;
  ERROR_UNHANDLED_EXCEPTION = 2;
};

int main(int argc, char** argv)
{
  try
  {
    std::string appName = boost::filesystem::basename(argv[0]);
    std::vector<std::string> decryption_infos;
    const string monitoring_interface;
    const string output_file_prefix("test");
    const string output_dir("/tmp");
    int total_capture_time = 0;
    int capture_time_per_file = 0;
    bool save_decrypted_packets_only = false;
    /** Define and parse the program options
     */
    namespace po = boost::program_options;
    po::options_description desc("Options");
    desc.add_options()
      ("help,h", "Print help messages")
      ("verbose,v", "print words with verbosity")
      ("decryption_infos,a", po::value<std::vector<std::string> >(&decryption_infos),
       "Specify the wpa:bssid:password or wep:bssid:password of APs whose packets need to be
       decrypted, you can specify multiple such combinations\n,
       Examples: wpa:MyAccessPoint:some_password or wep:00:01:02:03:04:05:blahbleehh")
      ("prefix,p", po::value<std::string>(&output_file_prefix)->default_value("trace"),
       "prefix for trace files, will produce files like <PREFIX-0.pcap>")
      ("outputdir,d", po::value<std::string>(&output_dir)->default_value("/tmp"),
       "prefix for trace files, will produce files like <PREFIX-0.pcap>")
      ("monitoriface,i", po::value<std::string>(&monitoring_interface)->required(),
       "monitoring interface for capture")
      ("decrypted_only,e", "Capture only decrypted 802.11 frames")
      ("captime,c", po::value<int>(total_capture_time)->default_value(0),
       "total capture time in secs (def. 0 will capture infinitely)")
      ("timeperfile,t", po::value<int>(capture_time_per_file)->default_value(0),
       "capture time per file in secs (def. 0 will capture in one file forever)");

    po::variables_map vm;

    try
    {
      po::store(po::command_line_parser(argc, argv).options(desc)
      .positional(positionalOptions).run(), vm); // throws on error

      /** --help option
       */
      if ( vm.count("help")  )
      {
        std::cout << "802.11 decryption tool" << std::endl;
        std::cout << desc << std::endl;
        return SUCCESS;
      }
      po::notify(vm); // throws on error, so do after help in case
      // there are any problems
    }
    catch(boost::program_options::required_option& e)
    {
      rad::OptionPrinter::formatRequiredOptionError(e);
      std::cerr << "ERROR: " << e.what() << std::endl << std::endl;
      return ERROR_IN_COMMAND_LINE;
    }
    catch(boost::program_options::error& e)
    {
      std::cerr << "ERROR: " << e.what() << std::endl << std::endl;
      return ERROR_IN_COMMAND_LINE;
    }

    if ( vm.count("decrypted_only") )
    {
      save_decrypted_packets_only = true;
    }

  }
  catch(std::exception& e)
  {
    std::cerr << "Unhandled Exception reached the top of main: "
      << e.what() << ", application will now exit" << std::endl;
    return ERROR_UNHANDLED_EXCEPTION;

  }
  // Setup everything and start decryption
  auto decrypters = parse_args(decryption_infos);
  Sniffer sniffer(monitoring_interface, 2500, false);
  const string output_file = output_file_prefix + "-0.pcap";
  PacketWriter writer(output_file, DataLinkType<RadioTap>());
  running = true;
  signal(SIGINT, sig_handler);
  continuous_decrypt(sniffer, writer, move(decrypters), output_file_prefix, output_dir,
    total_capture_time, capture_time_per_file, save_decrypted_packets_only);
  return 0;
}





