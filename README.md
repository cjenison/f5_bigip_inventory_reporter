# f5_bigip_inventory_reporter

This script takes an argument of a list of networks (e.g. 10.128.200.0/24 192.168.1.0/25) and will walk the network looking for the BIG-IP "TMUI" Login Page on port 443. When it finds that page, it grabs the hostname and will attempt (using credentials passed at script start) to authenticate via iControl REST and gather Model Number, Serial Number, Software Revision and the list of Provisioned Modules. With that data, it can either print to STDOUT (it prints JSON) or produce an XLSX
