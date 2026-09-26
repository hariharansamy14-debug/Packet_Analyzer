const express = require('express');
const path = require('path');
const { decodePacket } = require('./src/packet');
const db = require('./config/db');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '256kb' }));
app.use(express.static(path.join(__dirname, 'public')));

function serializePacket(value) {
    if (Buffer.isBuffer(value)) {
        return {
            hex: value.toString('hex'),
            length: value.length
        };
    }

    if (Array.isArray(value)) {
        return value.map(serializePacket);
    }

    if (value && typeof value === 'object') {
        return Object.fromEntries(
            Object.entries(value).map(([key, entry]) => [key, serializePacket(entry)])
        );
    }

    return value;
}

app.post('/api/analyze', async (req, res) => {
    const hex = typeof req.body?.hex === 'string' ? req.body.hex.replace(/\s+/g, '') : '';

    if (!hex || !/^[\da-f]+$/i.test(hex) || hex.length % 2 !== 0) {
        return res.status(400).json({ error: 'Enter a valid hexadecimal packet with complete bytes.' });
    }

    let packet;
    try {
        packet = serializePacket(decodePacket(Buffer.from(hex, 'hex')));
    } catch (error) {
        return res.status(400).json({ error: error.message });
    }

    try {
        const bytes = Buffer.byteLength(hex, 'hex');
        const [result] = await db.execute(
            'INSERT INTO analyzed_packets (packet_hex, decoded_packet, packet_bytes) VALUES (?, ?, ?)',
            [hex, JSON.stringify(packet), bytes]
        );
        return res.json({ id: result.insertId, packet, bytes });
    } catch (error) {
        console.error('Failed to store analyzed packet:', error.message);
        return res.status(503).json({
            error: 'Packet analysis succeeded, but saving failed. Check the database connection and try again.'
        });
    }
});

app.use((req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

async function startServer() {
    try {
        await db.query(`
            CREATE TABLE IF NOT EXISTS analyzed_packets (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                packet_hex LONGTEXT NOT NULL,
                decoded_packet JSON NOT NULL,
                packet_bytes INT UNSIGNED NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('MySQL database connection established.');
    } catch (error) {
        console.error(`MySQL database connection failed: ${error.message}`);
    }

    app.listen(PORT, () => {
        console.log(`Packet analyser is running at http://localhost:${PORT}`);
    });
}

startServer();