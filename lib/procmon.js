#!/usr/bin/env node
/*
  * procmon 0.1.1 by @chaseahiggins
  *****************************************************************************
  * naturally we need to be able to monitor these processes to get informtion
  * about the crashes and to detect hangs and other issues. we will use gdb.js
  * in order to talk to gdb. there are several interfaces calling themselves
  * gdb.js, but for now we use an unmodified version of the very simple one
  * by sha0 and the badchecksum.net security team. will likely be extended
  *****************************************************************************
  * BUGS/TODO:
    * separate exec into own function outside gdb exec
    * restrucure completely, need to merge handlers into respective namespaces
    * remove the simple logging and switch over to a more robust system
    * make gdb monitor mode use the new unified launcher utilities
  *****************************************************************************
*/

var fs = require('fs');
var child = require('child_process');
var gdb = require('gdb.js').gdb;
var path = require('path');

var procmon = procmon || {};

// procmon globals
procmon.cmd = [];
procmon.timers = [];

// you can hardcode your tweaks for now
procmon.opts = {
	debug: 1,
	dir: 'crashes'
};

// logging tools
procmon.logging = {
	logEvent: function(str) {
		/*
      * generic event log writer for the main application logfile
    */
	}, // end logEvent

};
// end logging, remove logCrash method at some point

procmon.logCrash = function(exploitable_out, cb) {
	/*
		* I don't know how, but they did it, man. the fuzzer, input, black magic whatever
		* they threw at our poor subject worked and now we log the juicy crash deets
  	*/
	// get classification
	var classification = exploitable_out.match(/CLASSIFICATION:([A-Z_]+)\b/);
	classification = classification ? classification[1] : "UNCLASSIFIED";
	// let's write a file with our findings for later analysis
	var buff = procmon.cmd[0] + " crashed in an interesting way at: " + String(new Date()) + "\n";
	buff += "It was ran as 'r " + procmon.cmd.slice(1).join(" ") + "' in gdb\n";
	buff += "----- Quick analysis via 'exploitable -m' in gdb follows -----";
	buff += "\n" + exploitable_out;
	var file_name = classification + "_";
	file_name += procmon.cmd[0].replace(/[^A-Za-z0-9_-]+/, "");
	var d = new Date();
	file_name += "_" + (d.getMonth() + 1) + "" + d.getDate() + "" + d.getFullYear() + "_" + d.getHours() + "" + d.getMinutes() + "" + d.getSeconds() + ".txt";
	// let's craft our output
	cb({
		file_name: file_name,
		buff: buff
	});
}; // end logcrash method

// generic process monitoring for instrumented bins
procmon.launchers = {
	launchProcess: function(cmd, monitor_opts, cb) {
		/*
			* launch a binary, we use this as the new generic
			* method for launching and it will accept the monitor
			* type as an option, so we can eliminate the gdb one
			* cmd should be array [bin, arg1, arg2,...,argn]
		*/
		// check up on args
		monitor_opts = monitor_opts || null;
		// make sure we have cmd array
		if (!Array.isArray(cmd)) throw "cmd is not an array";
		// decide on monitoring type
		if (!monitor_opts) {
			monitor_opts = {
				type: "gdb"
			};
		}
		switch (monitor_opts.type) {
			case "asan": // instrumented with asan/ubsan, good choice
				var p = child.exec(cmd.join(" "), function(err, stdout, stderr) {
					// asan stuff will be in stderr if there at all
					//console.log(stdout);
					procmon.handlers.asanExitHandler(stderr, cb);
				}); // end child exec
				break;

			case "none": // guess they just want to check coredumpctl or something like a goon
				break;

			case "gdb": // spawn process with gdb to allow crash detect/log with 'exploitable'
			default: // default is gdb
		}

	}, // end launchProcess method

};

// end launcher shit

procmon.handlers = {
	asanExitHandler: function(stderr, cb) {
		/*
			* call on exit for a bin that has asan/ubsan instrumentation. scan stderr and detect
			* if there were any recognizable issues, if so we'll log before moving on to the
			* next case, the logic for which should be there for us in cb
		*/
		//if (procmon.opts.debug) console.log("[i] handling asan exit: " + stderr);
		// see if we should try and log
		if (stderr.indexOf("==") === -1) {
			// pretty strong signal here
			return cb("not_exploitable");
		}
		// we'll need a few regexes to grab the most newsworthy info
		var regex = {
			reason: /==[\d]+==[\w]+:\s([\w]+):\s([\w-]+)/
		};
		// get reason for crash
		var reason;
		try {
			reason = stderr.match(regex.reason).slice(1);
			reason = reason[0].toLowerCase() + "_" + reason[1].replace(/-/g, "_");
		} catch(e) {
			reason = "unknown_crash";
		}
		// prepare a timestamp
		var d = new Date();
		// build file name
		var file_name = reason;
		file_name += "_" + (d.getMonth() + 1) + "" + d.getDate() + "" + d.getFullYear() + "_" + d.getHours() + "" + d.getMinutes() + "" + d.getSeconds() + ".txt";
		// cb when given an obj with file name and buffer will write a crashreport
		cb({
			file_name: file_name,
			buff: stderr
		});
	}, // end asanExitHandler

	onGDBExit: function(res) {
		/*
			* few things we'll want to do: analyze the exit is first
			* an a nornal exit, we'll assume that either the fuzzer killed
			* it or it exited for good reason. if we do see an unexpected
			* crash, we'll use the exploitable plugin for gdb to classify
			* the crash and if it is good we'll log the details into an
			* outfile for later analysis
		*/
		//console.log('onGDBExit');
		//console.log('res: ' + res);
	}, // end onGDBExit handler

	parseCmdResult: function(res, cb) {
		// clear outbuff
		procmon.gdb.out_buff = "";
		// let's see if we can classify the exit
		// clear the kill timer if it is there
		if (procmon.timers.length > 0) clearTimeout(procmon.timers.pop());
		// first, if it exited normally let's just move right on
		if (res.match(/exited\snormally/) || res.match(/exited\swith\scode/)) {
			// this one is over
			return cb("normal_exit");
		}
		var sig_regex = /received signal\s([A-Za-z\s,]+)\./;
		var m = res.match(sig_regex);
		var sig;
		try {
			sig = {
				signal: m[1].split(", ")[0],
				message: m[1].split(", ")[1]
			};
		} catch(e) {
			// something must be way fucked (or we are in an exploitable-spawned run)
			console.log('got caught');
			return setTimeout(function(){cb("not_exploitable");}, 0);
		}
		switch (sig.signal) {
				// interestings
			case 'SIGSEGV':
				// fall on through to dope
			case 'SIGILL':
				// fall on through to dope
			case 'SIGFPE':
				// fall on through to dope
			case 'SIGABRT':
				// fall on through to dope
			case 'SIGTRAP':
				// fall through because sometimes bins are helpful and want to let gdb try and save them
			case 'DOPE':
				// oh fuck yeah, let's throw a party
				console.log("[+] Found an interesting crash " + sig.signal);
        procmon.gdb.exploitable();
				break;
				// borings
			case 'SIGINT':
				// fall on through for boring
			case 'SIGTERM':
				// fall through for boring cases
			case 'NOT_DOPE':
				// botom of the fall through for anything, well, not dope
				console.log("[i] Subject exited with signal '" +
							sig.signal + ": " + sig.message +
							"', probably nothing");
				// yeah "probably" nothing but still, might as well ask
				procmon.gdb.exploitable().then(function(out) {
					// see what the classification is, if PROBABLY_NOT_EXPLOITABLE move on
					if (out.match(/PROBABLY_NOT_EXPLOITABLE/)) {
						console.log("[i] Confirmed boring crash, closing gdb");
						gdb.bin.kill(); // NO!
						cb("not_exploitable");
					}
					// oh shit, we might have overlooked something, call the logger
				});
				break;
			default:
				console.log('[!] could not handle signal: ');
				console.log(JSON.stringify(signal));
				var buff = "cmd: " + procmon.cmd.join(" ") + "\n";
				buff += JSON.stringify(signal) + "\n\n";
				fs.appendFileSync(procmon.opts.dir + "/unhandled_sigs.txt", buff);
		}
	}, // end parseCmdResult handler
};

// DFGKHDF FUTURTE CHASE
// where we are, is making sure exploitable works with outHandlerDispatch
// eright now it works good with first stage
procmon.gdb = {
	out_buff: "", // need some scratch space

	outHandlerDispatch: function(line, cb) {
		// see if we are ready to distpatch one of our output handlers
		// massive if-elseif-else chain woot
		// combine with prev stdout lines for handling
		procmon.gdb.out_buff += line;
		line = line.replace(/\n/, "");
		if (procmon.gdb.out_buff.match(/(terminated|received)\s(with\s)?signal/g)) {
			procmon.handlers.parseCmdResult(procmon.gdb.out_buff, cb);
		}
		else if (line.match(/exited\snormally/g) || line.match(/exited\swith\scode/)) {
			cb("normal_exit");
		}
		//else if (line.match(/\(?gdb\)?(-peda)?/g)) {
		else if (line.match(/done\.$/)) { // yeah, there are better ways but
			gdb.cmd("r " + procmon.cmd.join(" "), function(res) {
				//console.log('post cmd call in gdb cb');
			});
		}
		else if (line.match(/CLASSIFICATION/)) { // exploitable out, we get away with this as it is all one line
			procmon.logCrash(line, cb);
		}
	}, // end outputhandlerdispatcher

	launchProcess: function(cmd, opts, cb) {
		/*
			* launch a process in gdb and monitor the execution
			* for now we keep this real simple - we take a cmd arg as an
			* arr where cmd[0] is the command to execute and as many args
			* as needed to be joined by spaces (passed to gdb's "r" command)
		*/
		// first make sure we're ready to buffer fresh output
		procmon.gdb.out_buff = "";
		// save the command for later ref
		//procmon.cmd = cmd;
		// set output handler
		gdb.onStdout = function(data) {
			procmon.gdb.outHandlerDispatch(data.toString(), cb);
		};
		// override handlers to suppress output
		gdb.onClose = function() {
			return;
		};
		gdb.onStdoutEnd = function() {
			return;
		};
		procmon.cmd = Object.assign([], cmd);
		// let's get started
		// after start, register a timeout handler if we need to
		if (opts.kill_after) {
			procmon.timers.push(
				setTimeout(function() {
					gdb.bin.kill();
					cb("normal_exit");
				}, opts.kill_after * 1000)
			); // milliseconds
		} // end kill_after if
		// init it
		procmon.cmd[0] = ""; // to prevent bad comm join
		gdb.init(cmd[0], function() {
			// for if we ever need to do anything
			return;
		});
	}, // end launchProcess

	exploitable: function() {
		// a wrapper to call exploitable
		return new Promise(function(resolve, reject) {
			gdb.cmd("exploitable -m", function(res) {
				resolve(res);
			});
		});
	} // end exploitable method
}; // end gdb

procmon.standaloneMonitor = function(opts, cb) {
	/*
		* outside of fuzzing with newt, other fuzzers (inside browsers etc) that are not able to
		* interface with newt directly still often lack their own crash monitoring capabilities
		* they would appreciate a way to catch crashes that they cause without even having
		* to know about the monitor
	*/
	if (!opts.subject) throw "error: you must specify a subject";
	// decide on process monitoring and go for it
	switch (opts.monitoring.mode) {
		case "asan":
			console.log("[+] using asan monitor mode");
			opts.monitoring.launcher = procmon.launchers.launchProcess;
			opts.monitoring.opts = {}; // to be passed as options to a monitoring method
			break;

		case "gdb":
			console.log("[+] using gdb monitor mode");
			opts.monitoring.launcher = procmon.gdb.launchProcess;
			opts.monitoring.opts = {}; // for future opts to function use
			break;

		default:
			process.exit("[-] Unknown monitoring mode: " + opts.monitoring.mode);
	}
	// less do a
	opts.monitoring.launcher(opts.subject, {type: opts.monitoring.mode}, function(res){
		// let's see what we got back from our process
		if (res == "not_exploitable" || res == "normal_exit")  console.log("[+] " + opts.subject[0] + " looks to have exited in a uninteresting manner");
		if (res.buff) {
			if (!opts.out_dir) {
				console.log("[+] " + opts.subject[0] + " exited abnormally");
				console.log(res.buff);
			}
			else {// if we have access to out dir then of course we log
				try {
					console.log("[+] writing interesting crash data to: " + path.join(opts.out_dir, res.file_name));
					fs.writeFileSync(path.join(opts.out_dir, res.file_name), res.buff);
				} catch(e) {
					console.log("[!] could not write crash data, check if output dir exists and is accessable - exit info follows");
					console.log(res.buff);
				}
			}
		} // end handling of result buffer
		// if needed, we can respawn by just recursively calling with same args
		opts.respawn ? procmon.standaloneMonitor(opts, cb) : process.exit();
	});
}; // end standAloneMonitor


if (require.main === module) {
	try {
	} catch(e) {
		console.log(e);
	}
} else {
	module.exports = procmon;
}

