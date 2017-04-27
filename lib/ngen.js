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

  int: function(opts) {
    // return a int of opts.bits width
		opts = opts || {};
		if (!opts.bits) return this.byte();

	},

  junk: function(opts) {
    // fill a buffer with stuff
    if (opts.min_len && opts.max_len)
      opts.len = this.rand(opts.min_len, opts.max_len);
    else if (!(opts.min_len && opts.max_len) && !opts.len)
      opts.len = 4; // arbitrary, but whatevs
		
    this.buff += fuzzer.randBuff(opts.len, {});
  },

  enum: function(choices) {
    // choices might be like ["POST", "GET", "DELETE"]
    this.buff += choices[this.rand(0, choices.length)];
  },

  // helper funcs
	optCollector: function(opts, keys) {
		// help get args for a underlying function in the fuzzer or other newt module
		if (!Array.isArray(keys)) return -1;
		var params = {};
		for (var i = 0; i < opts.length; i++)
			if (keys.indexOf(opts[i])) params[keys[keys.indexOf(opts[i])]] = opts[i];
	},
	
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
