function bufferToArrayBuffer(buf) {
  var ab = new ArrayBuffer(buf.length);
  var view = new Uint8Array(ab);
  for (var i = 0; i < buf.length; ++i) {
    view[i] = buf[i];
  }
  return ab;
}

function arrayBufferToBuffer(ab) {
  var buf = Buffer.alloc(ab.byteLength);
  var view = new Uint8Array(ab);
  for (var i = 0; i < buf.length; ++i) {
    buf[i] = view[i];
  }
  return buf;
}

function arrayBufferToString(buf) {
  return arrayBufferToBuffer(buf).toString()
}
function stringToArrayBuffer(str) {
  return bufferToArrayBuffer(Buffer.from(str))
}

module.exports = {
  bufferToArrayBuffer,
  arrayBufferToBuffer,
  arrayBufferToString,
  stringToArrayBuffer
}