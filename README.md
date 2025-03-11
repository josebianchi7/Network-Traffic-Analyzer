# Network-Traffic-Analyzer

#### Microservice that sends an event message if it flags suspicious activity by a device on the local network, including use of unsecure protocols, requests with malformed packets, or requests to known malicious sites.

## Authors

- [@josebianchi7](https://github.com/josebianchi7)


## Deployment

To deploy this project, the following is required:

1. Install the following necessary Python libraries (if not already installed):

    For network packet sniffing:
    ```bash
      $ pip install scapy
    ```

2. Create credentials file, credentials.py, and include the following data in string format:
  
    1. url_notify = URL to notify network owner.




## References and Acknowledgements

[1] guedou GreHack, “Scapy in 0x30 Minutes Slides,” Github.io, 2022. https://guedou.github.io/talks/2022_GreHack/Scapy%20in%200x30%20minutes.slides.html#/ (accessed Mar. 08, 2025).

[2] L. Balaraman, “Packet Sniffing Using Scapy,” GeeksforGeeks, Jul. 01, 2021. https://www.geeksforgeeks.org/packet-sniffing-using-scapy/ (accessed Mar. 08, 2025).
