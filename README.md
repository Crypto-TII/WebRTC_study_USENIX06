# WebRTC-DTLS-Analysis-Proxy

A MitM-Analysis tool for DTLS connections. It captures UDP traffic on a network interface.
It forwards these packets or answers them itself if it thinks that they contain DTLS packets.

## Prerequisites

* Maven (tested with v3.8.8)
* JDK 21
* TLS-Attacker dependencies
  1. Protocol-Toolkit-BOM on branch webrtc_layer
  2. ModifiableVariable on branch webrtc_layer
  3. Protocol-Attacker-Development on branch webrtc_layer
  4. ASN.1-Attacker-Development on branch webrtc_layer
  5. X509-Attacker-Development on branch webrtc_layer
  6. TLS-Docker-Library-Development on branch webrtc_layer
  7. TLS-Attacker-Development on branch stun_layer
  8. Scanner-Core on branch webrtc_layer
  9. TLS-Scanner-Development on branch webrtc_layer
* A network setup as descibed in *Network Setup*
* If a full MitM is to be established with a browser (post-dtls/media tests), Chromium may be compiled with changed made to the DTLS certificate check behaviour as described in *Chromium Setup*

## Building

After building the TLS-Attacker dependencies run

```bash
$ mvn clean install
```

If you are experiencing issues with the tests or the java doc try

```bash
$ mvn clean install -Dmaven.test.skip=true -Dmaven.javadoc.skip=true
```

and try setting

```bash
$ export JDK_JAVA_OPTIONS="-Djdk.attach.allowAttachSelf=true"
```

for the Mockito test framework and

```bash
$ export JAVA_HOME="/usr/lib/jvm/java-21-openjdk-amd64"
```

for maven if not configured seperatly.

You should now be able to run

```bash
$ java -jar apps/WebRTC-Analysis.jar -help
```

## Network Setup

This analysis tool captures traffic from two network interfaces and reacts to it, sending traffic on both interfaces.
The interface facing the outside world will be called "outbound interface" while the interface facing the analysed application (here browser running WebRTC) will be called "inbound interface".

### Forwarding

As the tool will only filter and react to UDP traffic one might want to forward all other packets between inbound and outbound interface to ensure connectivity of the analysed application. This can be achieved with the iptables script in the repository:

```bash
$ sudo sh resources/forward.sh
```

Note that this script drops ICMP so you are not able to do ping checks on the target/victim machine.

### Enabling Interface Access

To use pcap4j, the java binary needs to have the rights to sniff from interfaces on the analysis machine.
This can be enabled with:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip <path to java>
```

f.e.

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/lib/jvm/java-21-openjdk-amd64/bin/java
```

### Example Setup

Here an example configuration using VirtualBox VMs:
* VM "Victim"
* network interface enp0s3
* VirtualBox internal network "analysis"
* static ip 10.10.11.4
* netmask 255.255.255.0
* gateway 10.10.11.5
* Selenium and Chromium installed
* VM "Analysis"
* network interface enp0s8 ("inbound")
* VirtualBox internal network "analysis"
* static ip 10.10.11.5
* netmask 255.255.255.0
* gateway 10.10.11.5
* network interface enp0s3 ("outbound")
* VirtualBox NAT or Bridge to the outside world / to a UDP peer
* dynamic ip
* Analysis-Proxy installed
* iptables forwarding script executed: UDP dropped, everything else forwarded

### Other

Optional: You may want to disable DNS over UDP on the victim machine and make sure your profiled program does not use QUIC to improve the tools latency.

## Running

### Automated Testing

If you wish to use the test automation feature you need to setup a couple things. Beware that test automation is error prone due to webapps changing their code and their possibly instable behaviour in establishing DTLS connections. It may still be worth it to give it a try as automation can prove very convenient and yield runtime improvements.

#### No Automation

Automation is not required, you can specify MANUAL in the target configuration, which will allow you to use your own program(s) to establish dtls connections. You will then read `TEST READY. Press call!` in the console when the tool is awaiting the next DTLS connection which is for you to trigger manualy and only upon this prompt.

#### Target Config

The target config is an xml file which lists the service the tool is supposed to test and essential data the tool is to input to these service, f.e. username, password, meeting url etc.
If you want to f.e. automatically profile the DTLS-SRTP of Discord on Chrome your `targets.xml` should look similar to this

```xml
<configList>
<targetConfigList>
  <targetName>DISCORD</targetName>
  <username>email@example.com</username>
  <password>examplePassword</password>
  <browsers>CHROME</browsers>
</targetConfigList>
</configList>
```

You can find examples of `targets.xml` in the resource folder.

#### Connection Config

Some applications may perform multiple DTLS connections to different servers per call, or may rotate distinct DTLS servers. To make sure we profile all distinct DTLS remote parties, there are some connection parameters that can be filtered for.
We say that a DTLS remote party is distinct from another when their initial JA3 fingerprint is different from the other remote parties. F.e. if an application sets up connection to a remote DTLS client with Client Hello fingerprint A, a remote DTLS server with Server Hello fignerprint B and a remote DTLS server with Server Hello fingerprint C then we say they are all distinct if B != C. If an application such as Zoom establishes two DTLS handshakes with a DTLS server which presents a Server Hello of the same JA3 fingerprint for each, then profiling one handshake suffices. Beware that load balancers may present a different endpoint / JA3 fingerprint at a later point in time. For this matter, it should be verified that upon tool termination, only one JA3 fingerprint is listed in the observed remote fingerprint section of the report.
Example:

```
--|Remote JA3s Server's seen

65277,49199,65281-23-11
```

To pin the tool to a specified DTLS endpoint, you can discard connections that do not fit your configured parameters. You may configure remote IP address, local port, remote port, JA3 Client Hello fingerprint, and handshake number of the call.

To this end, copy `resources/connectionConfig.sample.xml` to `resources/connectionConfig.xml` and edit it.

```xml
<connectionConfig>
    <targetHandshakeNumber>1</targetHandshakeNumber>
    <targetClientHelloJA3>65277,49195-49199-52393-52392-49161-49171-49162-49172-156-47-53,23-65281-10-11-35-13-14,29-23-24,0</targetClientHelloJA3>
    <targetLocalPort>12345</targetLocalPort>
    <targetRemotePort>12345</targetRemotePort>
    <targetRemoteAddress>192.168.100.2</targetRemoteAddress>
</connectionConfig>
```

#### Selenium server

To run the automation, the tool connects remotely to a Selenium instance on the profiled machine that opens a browser and clicks through the webapp.
You can download Selenium Server (Grid) here
https://www.selenium.dev/downloads/
The tool was tested with Selenium 4.16.1
Run the executable on the target machine to start the Selenium instance.

```bash
java -jar selenium-server-4.16.1.jar standalone --selenium-manager true -p 4444
```

`--selenium-manager true` should download all browser drivers automatically. Make sure the target/victim machine has tcp/internet access at this point.

### Choosing probes to run

The default set of probes run on the targets is hardcoded in the `IndividualTester.java` `createTestList()`. If you want to perform a full profile you do not need to edit anything there. If you choose to run only a specific scenario you may want to comment out the other probes from the list to reduce runtime. Certain probes however depend on each other. Lets say you would like to run the post-dtls EmptyClientCertReencryptProbe probe for example, which tries to establish a full MitM between vulnerable browser and vulnerable endpoint using an empty certificate, you will need the results of the SelfTestProbe, ClientVerifiesCertificateProbe and MissingMessageProbe to trigger the execution of the EmptyClientCertReencryptProbe. You may omit those probes if you omit the result checks in the EmptyClientCertReencryptProbe or set the required results in the report before the EmptyClientCertReencryptProbe is executed. (TODO: Find a better solution for this)

### Command line parameters

Now that you have finished the setup, picked your target application, setup Selenium or started a Webbrowser on the target machine you are ready to start the tool.

```
-targetConfig targets.xml -connectionConfig connectionConfig.xml -webDriverUrl http://10.10.11.4:4444 -fr -pdir /home/user/selenium/browserconfig -cbp /home/user/selenium/chrome123/chrome -bt 600 -timeout 300 -v -in enp0s8 -out enp0s3 -ip 10.10.11.4 -mpd 20000 -rec caps/debug -dumpMedia -ex_certs resources/rsa_sha256_fullchain.pem;resources/ecdsa_sha384_fullchain.pem -ex_keys resources/rsa_sha256_privatekey.pem;resources/ecdsa_sha384_privatekey.pem -exRetry 5 -onlyTestRemotePeer
```

* `-targetConfig targets.xml` points to the file with services to profile. In a very fast run this may be just JANUS_CUSTOM with a URL pointing to a local installation.
* `-connectionConfig connectionConfig.xml` points to the file details for which connection to filter. If you are unsure which remote JA3 fingerprints you will see, filter only for handshake number 1 and check the report for the fingerprints observed on different connections
* `-webDriverUrl http://10.10.11.4:4444` the endpoint of our Selenium Server, running on the target machine
* `-pdir /home/user/selenium/browserconfig` browser profile folder. F.e. if an application start an xdg open request, the denial is saved to this profile. The automation is not able to close this popup so having the denial stored in the profile is the only way to get around it automatically.
* `-cbp /home/user/selenium/chrome123/chrome` binary location of the Chrome/Chromium browser to launch and automate on. Only required if automation used.
* `-bt 300` Browser timeout. If the timeout (here 5 mins) after requesting a DTLS connection from the automation is exceeded is it assumed the app or the automation has broken and a new connection is attempted.
* `-timeout 300` Packet/Connection timeout. This is the duration TLS Attacker is going to wait for a package to arrive until is determines that it is not coming any more. TLS-Attacker will still send a certain amount of retransmissions after this timeout and wait again.
* `-v` Verbose. Medium log level.
* `-in enp0s8` Inbound interface. Name of the network interface to capture/send traffic on, pointing to the target.
* `-out enp0s3` Outbound interface. Name of the network interface to capture/send traffic on, pointing to the outside world.
* `-ip 10.10.11.4` IP of the victim application.
* `-rec caps/debug` save capture files to the folder caps/debug (will be created if not present. Overwrites (some) previous pcaps if present)
* `-mpd 20000` give the application 20 seconds after bypassing authentication to finish the call setup and send us media
* `-dumpMedia` save decrypted rtp/rtcp/dtls if any
* `-ex_certs resources/rsa_sha256_fullchain.pem;resources/ecdsa_sha384_fullchain.pem -ex_keys resources/rsa_sha256_privatekey.pem;resources/ecdsa_sha384_privatekey.pem` points to your trusted certificates for the trusted certificate acceptance tests
* `-fr` will try to reset some webpages in a more efficient manner, f.e. pressing the hangup button. Per default the webpage is closed entirely and a one called to live. This speeds up profiling a lot but is not implemented on all services. This has only effect if you use Selenium.
* `-exRetry 5` set the retries performed if probe failes with an error or does not receive an alert from the remote party as proof for an authentication check. Keep this value consistent f.e. 5
* `-onlyTestRemotePeer` will skip probes that test the client, which is going to be a browser, in this selenium setup. We need results only from the remote server here. Omit this flag if you profile a desktop application

If you profile manualy and your application will attempt reconnections itself while always presenting the same remote JA3 fingerprint, you may set `-sessionResetPause 1`. This disables the tool prompting you to confirm the connection breakdown and will right away take the next connection. You can also use something like `-sessionResetPause 10000` to have the tool wait 10 seconds until is automaticaly picks the next connection for services that enfore timeouts between calls, such as Wickr.

For additional and new flags see `$ java -jar apps/WebRTC-DTLS-Analysis-Proxy.jar -help`

## Chromium Setup

If a DTLS authentication bypass is found in the remote endpoint of a DTLS application, one is able to establish a full MitM by injecting an authentication bypass into the browser of the victim machine.
A nice browser to do so is Chromium as it is OpenSource and well documented.
A couple issues arrise however when doing so (see *Troubleshooting*).
It is advisable to build the browser on a native machine, not a VM as building the browser will take a lot of time and disk space.
Without dependencies Chromium needs 31 GB of disk space and hours of download and compile time with an SSD and a 32 thread CPU as of 2024.

Follow the official instructions on how to build the browser on your desired setup but generate the build directory using

```bash
gn args out/Default
```

and enter the following build arguments to enable proprietary codecs and some optimizations.

```bash
is_component_build = true
is_debug = false
blink_symbol_level = 0
v8_symbol_level = 0
symbol_level = 0
rtc_use_h264 = true
proprietary_codecs = true
media_use_ffmpeg = true
ffmpeg_branding = "Chrome"
# use_jumbo_build = true # no longer supported
```

The instructions can be found here https://www.chromium.org/developers/how-tos/get-the-code/

Now that the browser is compiled, navigate to the file `src/third_party/webrtc/rtc_base/openssl_stream_adapter.cc` and edit it.
Change `OpenSSLStreamAdapter::VerifyPeerCertificate` to ignore a fingerprint missmatch, f.e.:

```c++
bool OpenSSLStreamAdapter::VerifyPeerCertificate() {
  if (!HasPeerCertificateDigest() || !peer_cert_chain_ ||
      !peer_cert_chain_->GetSize()) {
    RTC_LOG(LS_WARNING) << "Missing digest or peer certificate.";
    return false;
  }

  unsigned char digest[EVP_MAX_MD_SIZE];
  size_t digest_length;
  if (!peer_cert_chain_->Get(0).ComputeDigest(
          peer_certificate_digest_algorithm_, digest, sizeof(digest),
          &digest_length)) {
    RTC_LOG(LS_WARNING) << "Failed to compute peer cert digest.";
    return false;
  }

/* This comments out the browser DTLS certificate check in WebRTC
  Buffer computed_digest(digest, digest_length);
  if (computed_digest != peer_certificate_digest_value_) {
    RTC_LOG(LS_WARNING)
        << "Rejected peer certificate due to mismatched digest using "
        << peer_certificate_digest_algorithm_ << ". Expected "
        << rtc::hex_encode_with_delimiter(peer_certificate_digest_value_, ':')
        << " got " << rtc::hex_encode_with_delimiter(computed_digest, ':');
    return false;
  }
*/

  // Ignore any verification error if the digest matches, since there is no
  // value in checking the validity of a self-signed cert issued by untrusted
  // sources.
  RTC_DLOG(LS_INFO) << "Accepted peer certificate.";
  peer_certificate_verified_ = true;
  return true;
}
```

This example may be obsolete any time as the codebase is constantly changing.
Save your changes and compile. Voilà, you have a vulnerable browser now. All that is left to do is to copy all build files under the `out` directory onto your target/victim machine.

When running Chromium you may need to pass `--no-sandbox` to avoid crashes, passing `--disable-quic` will improve the analysis proxy efficiency.

## Troubleshooting

#### DTLS connections are not recognised by the tool.

* Make sure you do not forward UDP between inbound and outbound interface
* Make sure you passed the outbound and inbound interfaces to the tool and make sure you passed them correctly
* Use Wireshark for further investigation

#### The Victim / Inbound machine does not have internet access.

* Make sure you forward TCP between analysis inbound and outbound interface
* Try turning all interfaces off and on again
* Double check your IP configuration
* Check VirtualBox adapter configuration
* Use Wireshark for further investigation

#### Probe not executed with "Probe not applicable"

* Results from previous, required probe missing. Check if all required results have been collected. Possibly use all probes.
* Remove applicable check if running a single probe for testing purposes
* Check if probe applicable to target. F.e. post-dtls probe was run on standard Chrome

#### Output is fludded with thread dumps

* This comes from pcap4j. Try to run the tool in the IntelliJ IDEA using debug mode

#### Custom Chromium crashes

* Build is unstable. Choose another commit, wait a few days and pull or choose another webapp
* If you are using a VM, Chromium may have issues with your hypervisor. Try different hypervisors, usualy KVM should work.

#### Webapp does not work on Chromium

* Build is unstable. Choose another commit, wait a few days and pull or choose another webapp
* Build is too novel for the app. Manualy investigate error and manualy try to mitigate by f.e. removing features from the SDP
* WebApp may block Chromium. Try setting another user agent with selenium
* WebApp may require DRM management or other codecs, investigate and choose different build flags

## Credits

Robert Merget, Technology Innovation Institute (TII), @ic0nz1\
Martin Bach, Technical University Darmstadt (TUDa), @deltatecs\
Lukas Knittel, Ruhr Universität Bochum (RUB), @kunte0
