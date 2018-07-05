#!/usr/bin/env node

var fs = require('fs');
var exec = require('child_process').exec;
var path = require('path');
var net = require('net');
var crypto = require('crypto');

// these belong to us
var procmon = require('./procmon');
var fuzz = require('./fuzzing');
var log = require('./logging');
var ngen = require('./ngen');

var Fuzzer = Fuzzer || {};

// set some things up for it
Fuzzer.run = {};
Fuzzer.run.config = {};
Fuzzer.run.base = "";
Fuzzer.run.case_num = 0;
Fuzzer.run.current = "";
Fuzzer.run.crashes = []; // store hashes to prevent duplicates

// setup the available buffer mutators
Fuzzer.fuzzMethods = [
  fuzz.seqBitFlip,
  fuzz.seqByteFlip,
  fuzz.buffMangler,
  fuzz.chunkSpew
];

// setup the helper methods namespace
Fuzzer.utils = {};

// parseArgs method
Fuzzer.utils.parseArgs = function(args) {
	// parse args from stdin
	for (var i = 0; i < args.length; i++) {
		var arg = args[i];
		switch (arg) {
			case "-i":
				// seeds dir
				args.seeds_dir = args[++i];
				continue;

			case "-k":
				// time to allow before killing proc
				args.kill_after = args[++i];
				continue;

			case "-o":
				// output directory
				args.out_dir = args[++i];
				continue;

			case "-s":
				// the fuzz subject
				args.subject = args[++i];
				continue;

			case "-f":
				// fuzz factor
				args.fuzz_factor = args[++i];
				continue;

			case "-m":
				// monitor mode, default gdb
				args.monitoring = {
					mode: args[++i],
					launcher: null
				};
				continue;

			default:
				console.log("[-] Unrecognized option: " + arg);
				continue;
		}
	}
	return args;
};

// nextCase method
Fuzzer.utils.nextCase = function(res) {
	// goes to the next case after the current one is exited, however that occurs
	res = res || false;
  //console.log(Fuzzer.run.config.monitoring.mode);
	if (res) {
		// we have results from a previous case that we can decide to handle
		// the first run will not have one. or maybe there are cases where
		// a subject does not produce one somehow either who knows
		if (res == "normal_exit") {
			// delete the boring case
			fs.unlinkSync(Fuzzer.run.current);
			console.log("[i] subject exited normally");
			log.logEvent(Fuzzer.run.config.out_dir, "deleting boring case " + Fuzzer.run.case_num);
		}
		else if (res.file_name) {
			// oh yeah, let's write this
      // hash and save crash to prevent duplicates
      var duplicate = false;
      var r;
      switch (Fuzzer.run.config.monitoring.mode) {
        case "gdb":
          r = /FAULTING_INSTRUCTION:(.*)\n/;
          break;

        case "asan":
          r = /AddressSanitizer:\s(.*)\s\(/;
          break;
      }
      try {
        var inst = res.buff.match(r)[1];
        var hash = crypto.createHash("md5").update(inst).digest("hex")
        if (Fuzzer.run.crashes.indexOf(hash) != -1) throw "duplicate";
        Fuzzer.run.crashes.push(hash);
      } catch (e) {
        if (e == "duplicate") {
          duplicate = true; // stop the save
          console.log("[-] skipped logging duplicate crash");
        }
        else
          console.log("[-] unable to create crash record, it may be duplicated");
      }
      // done handling crash save, do the writing and logging
      if (!duplicate) {
			  log.logEvent(Fuzzer.run.config.out_dir, "logging an interesting crash w00t");
			  fs.writeFileSync(path.join(Fuzzer.run.config.out_dir, "crashes", res.file_name), res.buff);
      }
		}
	}
	// let's pick a base seed at random
	var seed = Fuzzer.run.seeds[Math.floor(Math.random() * Fuzzer.run.seeds.length)];
	var name =  seed + "_case" + Fuzzer.run.case_num;
  // if the seeds are ngen files, we'll be generating a case from the ground up
  if (seed.indexOf('.ngen.js') != -1) { // kind of yuck, I know
    console.log("[i] thanks for taking the time to build an ngen file :) [" + seed +"]");
		ngen.runNgenerator(path.join(Fuzzer.run.config.seeds_dir, seed));
    seed = "ngen"; // recycle this one for later
    buff = ngen.buff;
  }
  else
	  var buff = fs.readFileSync(path.join(Fuzzer.run.config.seeds_dir, seed), 'binary').toString();
  // now fuzz the buff from the file if not generated
  if (seed != "ngen") {
    // choose a random fuzzer from the available methods unless once is specified
    var method = Math.floor(Math.random() * (Fuzzer.fuzzMethods.length - 0) + 0);
    buff = Fuzzer.fuzzMethods[method](buff, {
      step_floor: 8 * 8,
      step_ceil: 64 * 8
    });
  }
  if (Fuzzer.run.config.type == "autofuzz") { // netfuzz, for example does not need to write it
    try {
      fs.writeFile(path.join(Fuzzer.run.config.out_dir, "cases", name), buff, 'binary');
    } catch (e) {
      console.log("error creating case: " + e);
    }
  } // end "autofuzz" check
  // set the current case
	Fuzzer.run.current = path.join(Fuzzer.run.config.out_dir, "cases", name);
  // this is where we part ways - autofuzz and netfuzz need different things here
  switch (Fuzzer.run.config.type) {
    case "autofuzz":
      // run the process, fuzer config should be populated with launcher, hung during setup
      // will expect a func sig like: cmd, monitor_opts, callback(which is us, F.r.m.launcher)
      // can be hooked with any monitoring you like, making it very flexible
      if (!Fuzzer.run.config.monitoring.launcher) process.exit("[-] Must hang launch function prior to starting fuzz chain");
      // accounting
      log.logEvent(
        Fuzzer.run.config.out_dir,
        "fuzzing " + Fuzzer.run.config.subject + " with " + name + ", monitoring with " + Fuzzer.run.config.monitoring.mode
      );
      Fuzzer.run.config.monitoring.launcher(
        [Fuzzer.run.config.subject, path.join(Fuzzer.run.config.out_dir, "cases", name)], // bin, input file as arg as "std" cmd array
        Fuzzer.run.config.monitoring.opts, // opts
        Fuzzer.utils.nextCase // next in the chain once we're done, at some point expose this to hook custom nextCase
      );
      // inc case number
      Fuzzer.run.case_num++;
      break; // end autofuzz case

    case "netfuzz":
			console.log("[+] connecting to " + Fuzzer.run.config.host.hostname);
			var s = net.connect({
        port: Fuzzer.run.config.host.port,
        host: Fuzzer.run.config.host.hostname
      }, function() { // connect cb
        s.write(buff); // send the data
        s.destroy(); // close the connection
				// move on
        Fuzzer.utils.nextCase();
      });

      break; // end netfuzz case

    default:
      console.log("[!] no type set, is this an autofuzz or netfuzz round?");
      process.exit();
  } // end master switch
};

// the main event
Fuzzer.autoFuzz = function(opts) {
  // our job is to make sure nextCase has all it needs to start and maintain
  // the processing of the case chain
	if (!opts.subject) throw "error: you must specify a fuzzing subject";
	if (!opts.seeds_dir) throw "error: autofuzzing requires seeds cases";
	if (!opts.out_dir) throw "error: must specify an output directory";
	if (!opts.kill_after) opts.kill_after = 0; // subj autocloses after run, no need to sigkill
	if (!opts.fuzz_factor) opts.fuzz_factor = 24; // a reasonable default I think
  if (!opts.monitoring) opts.monitoring = {mode: "gdb"}; // we'll need one of those
  // some options require further assembly
  // decide on process monitoring and go for it
  switch (opts.monitoring.mode) {
    case "asan":
      opts.monitoring.launcher = procmon.launchers.launchProcess;
      opts.monitoring.opts = {type: "asan" /* temporary until I know wtf I am doing */}; // to be passed as options to a monitoring method
      break;

    case "gdb":
      opts.monitoring.launcher = procmon.gdb.launchProcess;
      opts.monitoring.opts = {}; // for future opts to function use
      break;

    default:
      process.exit("[-] Unknown monitoring mode: " + opts.monitoring.mode);
  }
  if (opts.kill_after) opts.monitoring.opts.kill_after = opts.kill_after;
  // done handling options, set the configuration
  Fuzzer.run.config = opts;
	// let's grab these base cases
	try {
		var seed_files = fs.readdirSync(opts.seeds_dir);
		Fuzzer.run.seeds = seed_files;
	} catch (e) {
		console.log("seed dir error: " + e);
		process.exit();
	}
  log.logEvent(opts.out_dir, "checking for/creating log file");
	// iterate the cases each num_permutations time
	// create the case dir
	try {
		fs.mkdirSync(path.join(opts.out_dir, "cases"));
	} catch (e) {
		//console.log("error creating cases dir: " + e);
	}
	try {
		fs.mkdirSync(path.join(opts.out_dir, "crashes"));
	} catch (e) {

	}
  // set our type so nextcase knows what's happening
  Fuzzer.run.config.type = "autofuzz";
	// looks like we are ready to begin the long process
	Fuzzer.utils.nextCase();
}; // end autoFuzz method


Fuzzer.netFuzz = function(opts) {
  /*
    * autofuzz was described once by someone as the "main event" but netfuzz
    * is here to say local format fuzzing is for bitches and that we're about
    * to get into some proto shit
  */
  if (!opts.seeds_dir) throw "error: autofuzzing requires seed cases";
	if (!opts.out_dir) throw "error: must specify an output directory";
  if (!opts.host) throw "error: must specify a host and port";
  if (opts.host.split(":").length == 2) {
    opts.host = {
      hostname: opts.host.split(":")[0],
      port: opts.host.split(":")[1],
    }
  }
  else {
    throw "error: make sure host and port are like wreet.xyz:1337";
  }
  log.logEvent(opts.out_dir, "starting a netfuzz session...");
  Fuzzer.run.config = opts;
  Fuzzer.run.config.type = "netfuzz"; // need to tell nextcase how to behave
	// let's grab these base cases
	try {
		var seed_files = fs.readdirSync(opts.seeds_dir);
		Fuzzer.run.seeds = seed_files;
	} catch (e) {
		console.log("seed dir error: " + e);
		process.exit();
	}
  Fuzzer.utils.nextCase();
}

module.exports = Fuzzer;
