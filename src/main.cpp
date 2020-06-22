#include <array>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>


/* UNIX/LINUX specific headers */
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/netfilter.h>
#include <linux/ip.h>

//sudo iptables -A INPUT -j NFQUEUE --queue-num 0

/* Lib specific */
extern "C" {
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/pktbuff.h>
}


/* C specific */
#include <cstring>
#include <cerrno>

using std::literals::string_literals::operator""s;

std::string errno2string(const int num)
{
    /* strerror is not thread-safe but i'm lazy to write good handler */
    return std::string{std::strerror(num)};
}

static int nfq_q_cb(struct nfq_q_handle *q, struct nfgenmsg *, struct nfq_data *nfad, void *) {
    nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
    if (!ph)
        throw std::runtime_error("Unable to parse packet header");

    std::uint8_t *raw_data = nullptr;

    int raw_data_sz{nfq_get_payload(nfad, &raw_data)};
    if (raw_data_sz < 0)
        throw std::runtime_error("Cannot get payload");

    auto pkt_b_free = [](pkt_buff *b) {pktb_free(b);}; //FIXME: I don't understand why i need a wrapper
    std::unique_ptr<pkt_buff, decltype(pkt_b_free)> pkt_buffer{pktb_alloc(AF_INET, raw_data, raw_data_sz, 0x1000),
                                                               pkt_b_free};

    if (!pkt_buffer)
        throw std::runtime_error("Cannot allocate pkt buffer");

    iphdr *ip{nfq_ip_get_hdr(pkt_buffer.get())};

    if (!ip)
        throw std::runtime_error("Unable to parse ip header");

    if(ip->protocol == IPPROTO_UDP)  {
        std::cout << __PRETTY_FUNCTION__ << std::endl;
        for(int i{0}; i < raw_data_sz; i++)
            std::cout << raw_data[i];
        std::cout << std::endl;
    }

    return nfq_set_verdict(q, ntohl(ph->packet_id), NF_ACCEPT, 0, nullptr) ;
}

void handle_packet() {
    auto close_nfq = [](nfq_handle *handle) { nfq_close(handle); }; // FIXME: handle ret val from nfq_close
    std::unique_ptr<nfq_handle, decltype(close_nfq)> nfq_handler{nfq_open(), close_nfq};

    if (!nfq_handler)
        throw std::runtime_error("Unable to initailize nfq handler");

    auto close_nfq_q = [](nfq_q_handle *handle) { nfq_destroy_queue(handle); }; // FIXME: handle ret val from nfq_destroy
    std::unique_ptr<nfq_q_handle, decltype(close_nfq_q)>
        nfq_q_handler{nfq_create_queue(nfq_handler.get(), 0, nfq_q_cb, nullptr), close_nfq_q};

    if (!nfq_q_handler)
        throw std::runtime_error("Unable to initialize nfq queue handler");

    if (nfq_set_mode(nfq_q_handler.get(), NFQNL_COPY_PACKET, UINT16_MAX) < 0) {
        throw std::runtime_error("Cannot set queue copy mode");
    }

    std::array<std::uint8_t, UINT16_MAX + 1> buffer;
    for(int fd{nfq_fd(nfq_handler.get())}; ;) {
        ssize_t packet_sz{recv(fd, buffer.data(), buffer.size(), 0)};


        if (packet_sz < 0)
            throw std::runtime_error("Unable to read packet: "s + errno2string(errno));

        nfq_handle_packet(nfq_handler.get(), reinterpret_cast<char *>(buffer.data()), static_cast<int>(packet_sz));
    }
}

int main() try {
    handle_packet();
    return 0;
} catch (std::exception const &e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
} catch (...) {
    std::cerr << "Unknown Exception" << std::endl;
    return EXIT_FAILURE;
}