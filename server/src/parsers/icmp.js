function getICMPTypeName(type) {

    switch (type) {

        case 0:
            return "Echo Reply";

        case 3:
            return "Destination Unreachable";

        case 5:
            return "Redirect";

        case 8:
            return "Echo Request";

        case 11:
            return "Time Exceeded";

        default:
            return "Unknown";
    }
}


function parseICMP(buffer) {
    if (!Buffer.isBuffer(buffer)) {
        throw new TypeError("Expected a Buffer");
    }

    // Minimum common ICMP header
    if (buffer.length < 8) {
        throw new Error("ICMP packet must be at least 8 bytes");
    }


    // --------------------------------
    // Byte 0
    // --------------------------------

    const type = buffer.readUInt8(0);

    const typeName = getICMPTypeName(type);


    // --------------------------------
    // Byte 1
    // --------------------------------

    const code = buffer.readUInt8(1);


    // --------------------------------
    // Bytes 2-3
    // --------------------------------

    const checksum = buffer.readUInt16BE(2);


    // --------------------------------
    // Bytes 4-5
    // --------------------------------

    const identifier = buffer.readUInt16BE(4);


    // --------------------------------
    // Bytes 6-7
    // --------------------------------

    const sequenceNumber = buffer.readUInt16BE(6);


    // --------------------------------
    // Payload
    // --------------------------------

    const payload = buffer.subarray(8);


    return {
        type,
        typeName,

        code,

        checksum,

        identifier,
        sequenceNumber,

        payload
    };
}


module.exports = {
    parseICMP
};