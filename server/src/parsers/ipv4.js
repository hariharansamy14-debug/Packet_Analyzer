function formatIPv4(buffer) {
     return Array.from(buffer).join(".")
}

function getProtocolName(protocolNumber) {
    switch(protocolNumber) {
        case 1:
            return "ICMP";
        case 6:
            return "TCP";
        case 17:
            return "UDP";
        default:
            return "Unknown";
    }
}

function parseIPv4(buffer) {
    if (!Buffer.isBuffer(buffer)) {
        throw new TypeError("Expected a Buffer");
    }

    if(buffer.length < 20) {
        throw new Error('Buffer frame must be at least 20 bytes');
    }

   const firstByte = buffer.readUInt8(0);
   const version = firstByte >> 4;
   const ihl = firstByte & 0x0f;
   const headerLength = ihl*4;

   if (version !== 4) {
       throw new Error("Unsupported IP version");
   }
   if (ihl < 5) {
       throw new Error("IPv4 header length must be at least 20 bytes");
   }
   if (headerLength > buffer.length) {
       throw new Error("IPv4 header is truncated");
   }

   const dscpAndEcn = buffer.readUInt8(1);
   const dscp = dscpAndEcn >> 2;
   const ecn = dscpAndEcn & 0x03;

   const totalLength = buffer.readUInt16BE(2);
   if (totalLength < headerLength) {
       throw new Error("IPv4 total length is smaller than its header");
   }

   const identification = buffer.readUInt16BE(4);

   const flagsAndFragmentOffset = buffer.readUInt16BE(6);

   const flags = flagsAndFragmentOffset >> 13;
   const fragmentOffset = flagsAndFragmentOffset & 0x1FFF;

   const ttl = buffer.readUInt8(8);
   const protocolNumber = buffer.readUInt8(9);
   const protocol = getProtocolName(protocolNumber);
   const checksum = buffer.readUInt16BE(10);

   const sourceIP = formatIPv4(buffer.subarray(12, 16));
   const destinationIP = formatIPv4(buffer.subarray(16, 20));

   const payload = buffer.subarray(headerLength, totalLength);
   return {
       version,
       ihl,
       headerLength,
       dscp,
                 ecn,
         totalLength,
         identification,
         flags,
         fragmentOffset,
         ttl,
         protocolNumber,
         protocol,
         checksum,
         sourceIP,
         destinationIP,
         payload
   };

}
module.exports = {
    parseIPv4
}