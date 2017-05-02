#!/usr/bin/env node

/*
  * newt.js, a simple node-powered fuzzer by @chaseahiggins
  *****************************************************************************
  * newt provides a simple, extensible method to perform file format fuzzing
  * by exposing various function hooks to set the monitoring and fuzz methods
  * newt makes it easy to add custom process monitoring/exit handling and
  * can easily be modified to accept more fuzzing methods. It is designed as
  * more of a framework with a format fuzzing module than a format fuzzer
  *****************************************************************************
  * BUGS/TODO:
	* the new standalone procmon reveals how tangled a mess things are, needs to be fixed fast <---||||f
	* unite arg parsers. like for fuck's sake what is this shit??
  * add the "none" monitoring mode
  * eliminate dependence on exploitable module in gdb mode
  * move crash logging deal to logging class
  * new fuzz modes:
		* "ripple" fuzz where we do simple arithmetic
			* of decreasing amountsaround an impact byte
		* rotate fuzz where we bitwise rotate a selection of byte(s)
		* basic arithmetics
    * chunk spew
	* add support for fuzzing cli args
  * add support for fuzzing via stdin
	* that master result obj needs to be consistent, and not fucked sometimes-str-sometimes-obj
	* look into deterministic fuzzing as suggested in lcamtuf's post
  * decentralize as much functionality as possible through hooks
	* port newt to windows including windbg monitor mode
	* use 'crash hashing' to detect and ignore duplicate crashes
	* autofuzz mode should should switch to exit code + message with next()
  * cache ngen files in memory to reduce tight file reads
  *****************************************************************************
*/

var fs = require('fs');

var newt = newt || {};
// our shit
newt.procmon = require('./lib/procmon');
newt.fuzzing = require('./lib/fuzzing');
newt.fuzzer = require('./lib/fuzz_director');

// options
newt.opts = {
  debug: 1
};


// cli interpretron time
if (require.main === module) {
  // we will keep cli stuff real simple, check first arg, exec accordingly
  switch (process.argv[2]) {
    case "randbuff": // random buffer
      // print a random buffer of argv[3] len
      if (process.argv.length < 4) {
        console.log("Generate a random string of a provided length:");
        console.log("\tuse: newt.js randbuff <str len>");
        console.log("\t ex: newt.js randbuff 32");
        process.exit();
      }
      var b = newt.fuzzing.randBuff(process.argv[3], {
        printable_only: 1
      });
      console.log(b);
      break;

		case "mutate": // mangle buffer
      if (process.argv.length < 3) {
        console.log("Take buffer from stdin, mangle every fuzz factor bytes and print to stdout:");
        console.log("\tuse: newt.js mutate <fuzz factor>");
        console.log("\t ex: cat seed.jpg | ./newt.js mutate 32 > case.jpg");
        process.exit();
      }
      // take a stdinput, mangle it to stdout
      process.stdin.resume();
      process.stdin.setEncoding('utf8');
      process.stdin.on('data', function(buff) {
        var b = newt.fuzzing.buffMangler(buff, {
          fuzz_factor: process.argv[3] ? process.argv[3] : 24
        });
        console.log(b);
      });
      break;

		case "autofuzz": // go through and fuzz a subject automagically
			var opts = newt.fuzzer.utils.parseArgs(process.argv.slice(3));
			newt.fuzzer.autoFuzz(opts);
			break;

    case "netfuzz": // much like autofuzz, but assuming the local instance unable to procmon
      /*
        * for now, we will just use sockets I guess, and assume that the ngen file
        * has taken care of the hard work of describing the correct protocol
      */
      var args = process.argv.slice(3);
      for (var i = 0; i < args.length; i++) {
        var arg = args[i];
				switch (arg) {
          case "-h":
            // set the host:port
            args.host = args[++i];
            break;

          case "-o":
            // out dir
            args.out_dir = args[++i];
            break;

          case "-i":
            // seeds dir
            args.seeds_dir = args[++i];
            break;
        }
      } // end options iteration
      newt.fuzzer.netFuzz(args);
      process.exit();


      break; // end netfuzz

		case "procmon": // simply spawn a proc to mon, fuzzing will happen elsewhere
			// parse args from stdin
		  var args = process.argv.slice(3);
			for (var i = 0; i < args.length; i++) {
				var arg = args[i];
				switch (arg) {
					case "-r":
						// respawn proc if crashes
						args.respawn = true;
						continue;

					case "-o":
						// output directory
						args.out_dir = args[++i];
						continue;

					case "-s":
						// the fuzz subject
						// special case where we may need to collect multiple
						var cmd = [];
						while (args[++i] && args[i].indexOf("-") !== 0 && i < args.length) // find all opts
							cmd.push(args[i]); // append to the cmd arr
						// now set it all
						args.subject = cmd;
						i -= 1;
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
				} // end switch
			} // end for
		  	newt.procmon.standaloneMonitor(args, null);
			break;

    default:
		  // help case
		  console.log("[~] newt.js " + require('./package.json').version + " - a simple node-powered fuzzer");
		  console.log("Usage: newt command [opts]\n");
		  console.log("Commands:");
		  // autofuzz
		  console.log("  autofuzz    Automatically generate cases and fuzz the subject");
		  console.log("  |  -i       Required, directory where file format or ngen seeds can be found");
		  console.log("  |  -o       Required, output directory for crashes, logs, cases");
		  console.log("  |  -s       Required, the subject binary to fuzz");
		  console.log("  |  -k       Sometimes required, kill subject after -k seconds, useful for GUI bins");
		  console.log("  |  -f       Optional, int value that translates to fuzzing 1/-f byte in buffMangler mode");
		  console.log("  |  -m       Optional, monitor mode. Default is gdb, asan instrumented bins also supported");
		  console.log(); // newline
		  // procmon
		  console.log("  procmon     Launch and monitor a process");
		  console.log("  |  -s       Required, the subject binary [with args]");
		  console.log("  |  -m       Required, monitor mode [asan|gdb]");
		  console.log("  |  -r       Optional, respawn process on exit");
		  console.log("  |  -o       Optional, output dir. Results printed to console if none specified");
      console.log();
      // netfuzz
      console.log("  netfuzz     Launch and monitor a process");
		  console.log("  |  -o       Required, output directory for crashes, logs, cases");
      console.log("  |  -h       Required, the host to send the fuzz case as host:port");

      // randbuff

      // mutate
  } // end comm switch
} // end arg handling

