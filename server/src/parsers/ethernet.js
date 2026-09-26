const { getEtherTypeName } = require("../utils/protocols");

function formatMAC(buffer){

    return Array.from(buffer).map(byte => byte.toString(16).padStart(2, '0')).join(':');

}


function parseEthernet(buffer){

    if (!Buffer.isBuffer(buffer)) {
        throw new TypeError('Expected a Buffer');
    }

    if (buffer.length <14){

        throw new Error('Ethernet frame must be at least 14 bytes');
    }


    const destinationMAC = formatMAC(buffer.subarray(0,6));
    const sourceMAC =  formatMAC(buffer.subarray(6,12));

    const etherType = buffer.readUInt16BE(12);

    return {
        destinationMAC,
        sourceMAC,
        etherType,
        protocol: getEtherTypeName(etherType),
        payload : buffer.subarray(14)
    };

}
module.exports = {
    parseEthernet
}