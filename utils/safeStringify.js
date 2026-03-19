
function safeStringify(value, space = 2) {
    const seen = new WeakSet();
    return JSON.stringify(
        value,
        (key, val) => {
            if (typeof val === 'bigint') return val.toString();
            if (typeof val === 'object' && val !== null) {
                if (seen.has(val)) return '[Circular]';
                seen.add(val);
            }
            // Avoid dumping huge request/response objects if they sneak in
            if (key === 'socket' || key === 'request' || key === 'response') return `[${key}]`;
            return val;
        },
        space
    );
}

module.exports = { safeStringify };