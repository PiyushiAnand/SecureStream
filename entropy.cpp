#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <iostream>
#include <vector>
#include <cmath>
#include <cstring>
#include <chrono>
#include <thread>
#include <map>
using namespace std;

double THRESHOLD = 5.05; // Set a threshold for entropy
int perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                    int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu,
                   group_fd, flags);
}

double compute_entropy(const std::vector<long long>& data) {
    if (data.empty()) return 0.0;
    std::map<long long, int> freq;
    for (auto val : data) {
        freq[val]++;
    }

    double entropy = 0.0;
    double total = static_cast<double>(data.size());
    for (const auto& [val, count] : freq) {
        double p = count / total;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

int main() {
    constexpr int SAMPLE_COUNT = 50;
    constexpr int SAMPLE_INTERVAL_MS = 100;

    struct perf_event_attr pe;
    std::memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = PERF_COUNT_HW_CACHE_MISSES;
    pe.disabled = 0;
    pe.exclude_kernel = 0;
    pe.exclude_hv = 1;

    int fd = perf_event_open(&pe, 0, -1, -1, 0);
    if (fd == -1) {
        perror("perf_event_open failed");
        return 1;
    }

    std::vector<long long> samples;

    std::cout << "Starting continuous entropy monitoring...\n";
    double avg_entrpoy = 0;
    int i=0;
    while (true) {
        
        long long value = 0;
        ssize_t res = read(fd, &value, sizeof(long long));
        if (res != sizeof(long long)) {
            std::cerr << "Failed to read perf counter\n";
            break;
        }

        samples.push_back(value);

        // Reset counter for next delta
        ioctl(fd, PERF_EVENT_IOC_RESET, 0);

        if (samples.size() >= SAMPLE_COUNT) {
            i++;
            double entropy = compute_entropy(samples);
            std::cout << "Entropy (last " << SAMPLE_COUNT << " samples): "
                      << entropy << " bits\n";
            avg_entrpoy = avg_entrpoy+entropy;
            samples.clear();
            if(i>0&&i%5==0){
                std::cout << "Average Entropy: " << avg_entrpoy/5 << " bits\n";
               
                if(avg_entrpoy/5<THRESHOLD){
                        cout<<"Potential attack detected!"<<endl;
                }
                avg_entrpoy = 0;
            }

        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(SAMPLE_INTERVAL_MS));
    }

    close(fd);
    return 0;
}
