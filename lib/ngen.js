var fs = require("fs");

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
		this.buff += this.rand((opts.min ? opts.min : 0), (1 << opts.bits) - 1);
	},

  junk: function(opts) {
    // fill a buffer with stuff
    if (opts.min_len && opts.max_len)
      opts.len = this.rand(opts.min_len, opts.max_len);
    else if (!(opts.min_len && opts.max_len) && !opts.len)
      opts.len = 4; // arbitrary, but whatevs
		this.buff += fuzzer.randBuff(opts.len, this.optCollector(opts, ["printable_only"]));
  },

  enum: function(choices) {
    // choices might be like ["POST", "GET", "DELETE"]
    this.buff += choices[this.rand(0, choices.length)];
  },

  // helper funcs
	optCollector: function(opts, keys) {
		// help get args for a underlying function in the fuzzer or other newt module
    // we... use this in an odd way
		if (!Array.isArray(keys)) return -1;
		var params = {};
    for (var i = 0; i < keys.length; i++)
      if (opts[keys[i]])
        params[keys[i]] = opts[keys[i]];
    return params;
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
  },

  runNgenerator(path) {
    // yeah I don't like it either, but not sure how else to structure things
		this.buff = ""; // clear it out first
    var buff = fs.readFileSync(path);
		eval(buff.toString("ascii")); // should fill this.buff
  }
};


module.exports = ngen;
