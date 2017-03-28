#!/usr/bin/env node

var fs = require('fs');
var exec = require('child_process').exec;
var sleep = require('sleep');
var path = require('path');

var procmon = require('./procmon');
var fuzz = require('./fuzzing');
var log = require('./logging');

var Fuzzer = Fuzzer || {};

// set some things up for it
Fuzzer.run = {};
Fuzzer.run.config = {};
Fuzzer.run.base = "";
Fuzzer.run.case_num = 0;
Fuzzer.run.current = "";

// setup the available buffer mutators
Fuzzer.fuzzMethods = [
  fuzz.seqBitFlip,
  fuzz.seqByteFlip,
  fuzz.buffMangler
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
			log.logEvent(Fuzzer.run.config.out_dir, "logging an interesting crash w00t");
			fs.writeFileSync(path.join(Fuzzer.run.config.out_dir, "crashes", res.file_name), res.buff);
		}
	}
	// let's pick a base seed at random
	var seed = Fuzzer.run.seeds[Math.floor(Math.random() * Fuzzer.run.seeds.length)];
	var name =  seed + "_case" + Fuzzer.run.case_num;
	var buff = fs.readFileSync(path.join(Fuzzer.run.config.seeds_dir, seed), 'binary').toString();
  // now fuzz the buff from the file
  // choose a random fuzzer from the available methods unless once is specified
  var method = Math.floor(Math.random() * (Fuzzer.fuzzMethods.length - 0) + 0);
  buff = Fuzzer.fuzzMethods[method](buff, {
    step_floor: 8 * 8,
    step_ceil: 64 * 8
  });
	try {
		fs.writeFile(path.join(Fuzzer.run.config.out_dir, "cases", name), buff, 'binary');
  } catch (e) {
		console.log("error creating case: " + e);
	}
  // set the current case
	Fuzzer.run.current = path.join(Fuzzer.run.config.out_dir, "cases", name);
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
	// looks like we are ready to begin the long process
	Fuzzer.utils.nextCase();
}; // end autoFuzz method

module.exports = Fuzzer;

