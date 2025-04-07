/**
 * Guesses the operating system based on TTL (Time To Live) and TCP window size.
 *
 * Many operating systems use default TTL and window size values in their TCP/IP stacks.
 * By analyzing these values in received packets (especially TCP SYN-ACK), we can make
 * a best-effort guess at the OS type behind the IP.
 *
 * @param ttl           Time To Live value from the IP header
 * @param window_size   TCP window size from the TCP header
 * @return              A string describing the guessed operating system
 */

const char* guess_os(int ttl, int window_size) {
    if (ttl >= 64 && ttl <= 65) {
        if (window_size == 5840) return "Linux (2.4/2.6)";
        if (window_size == 5720) return "Google Linux";
        if (window_size == 65535) return "Linux (Modern)";
        if (window_size == 64240) return "OpenSSH/Linux (Debian)";
        return "Linux-based";
    }
    if (ttl >= 128 && ttl <= 129) {
        if (window_size == 8192) return "Windows XP";
        if (window_size == 65535) return "Windows 7/10/11";
        return "Windows-based";
    }
    if (ttl >= 255) {
        if (window_size == 4128) return "Cisco Router";
        return "Network Device (maybe Cisco)";
    }
    if (ttl <= 40 && window_size == 64240)
        return "Linux (OpenSSH default)";
    return "Unknown OS";
}