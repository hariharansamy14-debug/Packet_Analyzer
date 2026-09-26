function  getEtherTypeName (etherType){
    switch(etherType){
        case 0x0800:
            return "IPv4";

        case 0x0806:
            return "ARP";

        case 0x86DD:
            return "IPv6";

        default:
            return "Unknown";
    }
}
module.exports = {
    getEtherTypeName
}