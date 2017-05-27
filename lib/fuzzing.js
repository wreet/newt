/*
	* potential new mutators: chunkspew, special ints and binary arithmetic
*/

var fuzz = {
  buffMangler: function(buff, opts) {
    /*
      * a very simple fuzzing strategy adapted from python code presented
      * by charlie miller in ios hackers handbook. it chooses a random byte
      * in the input buffer, and chooses a random byte value to replace it.
      * essentially it will do this every fuzz_factorth byte in the input
      * it does not do this sequentially, indeed same byte could be chosen
    */
    if (!opts) {
      opts = { // defaults if we need
        fuzz_factor: 24 // replace every fuzz_factorth byte, default 24
      };
    }
    // take a buff, fuckulate it according to opts

		buff = buff.split("");
    var num_writes = Math.floor(Math.random() * (Math.ceil(buff.length / opts.fuzz_factor)));
    for (var i = 0; i < num_writes; i++) {
      // iterate buff replace random bytes
      var rb = Math.ceil(Math.random() * (256)); // random valid byte
      var rl = Math.ceil(Math.random() * (buff.length)); // random location in buff
      buff[rl] = String.fromCharCode(rb);
    } // end iteration
    return buff.join("");
  }, // end buffMangler methhod

  randBuff: function(len, opts) {
    // generate random buffer (slowwwwww)
    opts = opts || {};
    var buff = [];
    for (var i = 0; i < len; i++) {
      if (opts.printable_only) // skip "control chars" 0-32
        buff.push(String.fromCharCode(Math.floor(Math.random() * (255 - 32 + 1)) + 32));
      else
        buff.push(String.fromCharCode(Math.ceil(Math.random() * (256))));
    }
    return buff.join(""); // is the buff returned reversed if it has no order?!?!
  }, // end buffmangler

  // let's try a few smarter methods
  // inspired by lcamtuf's fuzzing strategies at:
  // https://lcamtuf.blogspot.ca/2014/08/binary-fuzzing-strategies-what-works.html
  seqBitFlip: function(buff, opts) {
    /*
      * sequentially walk the input and perform bit flips
      * theoretically a softer touch than flipping 8 at a time for bytes
      * TODO
        * add flip for sequence of bits 1-4 on stop
    */
    // take care of options
    opts = opts || {};
    if (!opts.step_floor) opts.step_floor = (16 * 8) -1;
    if (!opts.step_ceil) opts.step_ceil = (48 * 8) - 1;
    if (opts.hard_step) opts.step_floor = opts.step_ceil = opts.hard_step; // if that's what they want
    // turn the input into a bytestream we can work with
    buff = new Buffer(buff, "binary");
    // this will be cray
    var i = Math.floor(Math.random() * (opts.step_ceil - opts.step_floor + 1) + opts.step_floor); // seedy
    while (i < buff.length * 8) { // bits man, bits
      var offset = Math.floor(i / 8);
      var byte = buff.readUInt8(offset, true);
      var bit = i % 8;
      byte = byte ^ (1 << bit); // flip bit'th bit from mask
      // write it at that offset
      buff.writeUInt8(byte, offset, true);
      // increment cursor
      i += Math.floor(Math.random() * (opts.step_ceil - opts.step_floor + 1) + opts.step_floor); // step it
    }
    return buff.toString('binary');
  }, // end seqBitFlip

  seqByteFlip: function(buff, opts) {
    /*
      * sequentially walk the input and perform byte flips
    */
    opts = opts || {};
    if (!opts.step_floor) opts.step_floor = 16;
    if (!opts.step_ceil) opts.step_ceil = 64;
    if (opts.hard_step) opts.step_floor = opts.step_ceil = opts.hard_step; // if that's what they want
    // let's do it
    buff = new Buffer(buff, "binary");
    // walk it
    var i = Math.floor(Math.random() * (opts.step_ceil - opts.step_floor + 1) + opts.step_floor); // start it
    while (i < buff.length) {
      // let's flip it
      buff[i] = ~buff[i];
      i += Math.floor(Math.random() * (opts.step_ceil - opts.step_floor + 1) + opts.step_floor); // step it
    }
    return buff.toString('binary');
  }, // end seqByteFlip

  chunkSpew: function(buff, opts) {
    /*
      * copy data from one location to another
    */
    if (!opts) {
      opts = { // defaults if we need
        fuzz_factor: 24, // spew buff.size / fuzz_factor locations
      };
    }
    if (!opts.copy) opts.copy = 0; // if true buffer may grow as chunk is duplicated
    if (!opts.chunk_max_size) opts.chunk_max_size = 32; // max chunk size in bytes
    buff = new Buffer(buff, "binary");
    var n = Math.floor(Math.random() * (Math.ceil(buff.length / opts.fuzz_factor)));
    console.log("n = " + n);
    for (var i = 0; i < n; i++) {
      // pick a src, dst and copy len
      var src = Math.ceil(Math.random() * (buff.length)); // random location in buff
      var dst = Math.ceil(Math.random() * (buff.length));
      var len = Math.ceil(Math.random() * (opts.chunk_max_size));
      // some arr manip
      var chunk = buff.slice(src, src + len);
      len = chunk.length;
      console.log("[chk, src, dst, len]: '" + chunk + "', " + src + ", " + dst + ", " + len);
      var tmp = buff.slice(0, dst) + chunk;
      buff = tmp + buff.slice(((opts.copy) ? tmp.length - len : tmp.length));
    }
    return buff.toString("binary");
  }, // end chunkSpew

  specialInts: function(buff, opts) {
    /*
      * insert troublesome ints and magic numbers
    */
  } // end specialInts


}; // end fuzz

module.exports = fuzz;
