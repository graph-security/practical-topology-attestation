# practical-topology-attestation

## Setup for new host or virtual machine
- based on ubuntu 20.04
- install java
    - `sudo apt install openjdk-8-jdk`
- install gcc-5
    - add if it does not exist
    
    ```bash
    deb http://gb.archive.ubuntu.com/ubuntu/ bionic universe
    ```
    
    to sources.list
    
    `sudo **vi** /etc/apt/sources.list`
    
    ```jsx
    sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 3B4FE6ACC0B21F32
    ```
    
    `sudo apt update`
    
    `sudo apt install gcc-5 g++-5` 
    
    `sudo apt install curl`
    
- install gcc-9
    - gcc version 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)
    - `sudo apt install gcc-9 g++-9`
- install gmp library
    - `sudo apt install libgmp10-dev`
- `sudo apt install openssl`
- `sudo apt-get install libssl-dev`
- `sudo apt-get install dh-autoreconf libssl-dev libtasn1-6-dev pkg-config net-tools iproute2 libjson-glib-dev libgnutls28-dev expect gawk socat libseccomp-dev make -y`
- `mkdir /home/username/DEV/test-tpm`
- `sudo apt-get install byobu tmuxinator` swig3.0
    - configure tmuxinator
        - `mkdir ~/.config/tmuxinator`
        - `vi ~/.config/tmuxinator/daa.yml`
            - edit configuration file
            
            ```yaml
            # /home/username/.config/tmuxinator/daa.yml                                                                                                       
            name: daa    
            root: ~/    
            tmux_command: byobu    
            windows:    
              - swtpm: cd /home/username/DEV/test-tpm    
              - trousers: cd /home/username/DEV/trousers-tss    
              - daa: cd /home/username/DEV/trousers-tss/src/tspi/daa
            ```
            
- `tmuxinator start daa`
- `sudo apt install tpm-tools`
- `sudo apt install trousers`
- build and install libtpms if using a software tpm
- build and install swtpm if using a software tpm
    - use ppa for latest deb
        - `sudo add-apt-repository ppa:stefanberger/swtpm`
    - install gnutls-bin
        - `sudo apt-get install gnutls-bin`
    - test vtpm-proxy under tests/ folder
        - `sudo ./test_vtpm_proxy`
    - start vTPM manufacturing and generating EK
    
    ```bash
    mkdir /tmp/mytpm
    ```
    
    ```bash
    sudo swtpm_setup --tpmstate /tmp/mytpm/ --create-ek-cert --create-platform-cert --lock-nvram
    
    sudo swtpm chardev --vtpm-proxy --tpmstate dir=/tmp/mytpm --ctrl type=unixio,path=/tmp/mytpm/swtpm-sock --log level=20
    ```
    
- transfer `trousers-tss` code to the host DEV folder
    - `chmod +x cleanup.sh`
- rebuild trousers stack and install it
    - `./cleanup.sh && sh [bootstrap.sh](http://bootstrap.sh/) && ./configure --enable-debug --with-gmp && make all && sudo make install`
- start trousers daemon
    - `sudo  tcsd -f`
- `cd  trousers-tss/src/tspi/daa`

```jsx
make clean 
make all
```

- execute `./issuer_setup`
- check if ek is created using
    - `tpm_getpubek -z -l debug`
- take ownership of the tpm
    - `tpm_takeownership -y -z -l debug`
- execute `./test_join`
- execute `./test_sign`
