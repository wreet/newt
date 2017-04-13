var fuzzer = require("./fuzzing");

var ngen = ngen || {};

ngen = {
	buff: "", // the output buffer

  // the blocks
	literal: function(str) {
		this.buff += str;
	},

	byte: function(opts) {
    // return a general purpose random byte
    this.buff += fuzzer.randBuff(1, {});
	},

  word: function(opts) {
    // return a general purpose random word
  },

  dword: function(opts) {
    // return a general purpose random dword
  },

  qword: function(opts) {
    // return a general purpose random qword
  },

  int: function(opts) {
    // return a int of opts.bits width
  },

  junk: function(opts) {
    // fill a buffer with stuff
    if (!opts.len) opts.len = 4; // not much to do but return a dword like a boss
    if (opts.variance) {
      // they want to give it a little whoa
      opts.len = this.rand(opts.len - opts.variance, opts.len + opts.variance);
      if (opts.len < 1) { // they didn't say zero, so don't give it to them
        try {
          return this.junk(opts); // let's see if we can do better
        } catch(e) {
          console.log("[!] got too deep on the retries");
          opts.len = 1; // no bueno
        }
      }
    }
    this.buff += fuzzer.randBuff(opts.len, {});
  },

  enum: function(choices) {
    // choices might be like ["POST", "GET", "DELETE"]
    this.buff += choices[this.rand(0, choices.length)];
  },

  // helper funcs
  toHex: function(str) {
    // get hex rep
    return new Buffer(str).toString('hex');
  },

  toBin: function(str) {
    // return str as binary buffer for file format fuzzing
    return new Buffer(str).toString("binary");
  },

  rand: function(min, max) {
    min = Math.ceil(min);
    max = Math.floor(max);
    return Math.floor(Math.random() * (max - min)) + min;
  }
};


module.exports = ngen;