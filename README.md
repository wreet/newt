# newt.js

An easy to use fuzzer designed to work with OOB or instrumented programs. 

## usage
```
[~] newt.js 0.6.0 - a simple node-powered fuzzer
Usage: newt command [opts]
Specify any command with no options for more usage information

Commands:
  autofuzz    Automatically generate cases and fuzz the subject
  |  -i       Required, directory where file format or ngen seeds can be found
  |  -o       Required, output directory for crashes, logs, cases
  |  -s       Required, the subject binary to fuzz
  |  -k       Optional, kill subject after -k seconds, useful for GUI bins
  |  -f       Optional, int value that translates to fuzzing 1/-f byte in most mutators
  |  -m       Optional, monitor mode. Default is gdb, asan instrumented bins also supported
  |  -x       Optional, comma-separated list of mutators(e.g. ripple,chunkspew) default is all
  |  -p       Optional, preserve non-crashing cases so they can be examined or used elsewhere

  procmon     Launch and monitor a process
  |  -s       Required, the subject binary [with args]
  |  -m       Required, monitor mode [asan|gdb]
  |  -r       Optional, respawn process on exit(flag takes no args)
  |  -o       Optional, output dir. Results printed to console if none specified

  netfuzz     Fuzz a remote network service
  |  -i       Required, directory where ngen seeds can be found
  |  -o       Required, output directory for logs, cases
  |  -h       Required, the host to send the fuzz case as host:port

  randbuff    Generate a random string for use elsewhere
  |  -l       Required, length of string to generate

  mutate      Mutate an input buffer from stdin, write it to stdout
  |  -f       Required, fuzz factor for the input buffer
  |  -x       Required, the mutator to use(e.g. ripple)
```

## features
newt.js does quite a lot - it can generate and run through test cases completely unattended with two built-in monitoring modes: gdb or asan. It has several built-in mutators, all of which can accept an options array for tweaking functionality. It's designed for extensibility - you can hang whatever function you want on almost any method utilized by the fuzzer, allowing it to adapt to new monitoring modes or mutators with minimal hassle.

newt is intended to be easy to use and flexible, so you can fuzz just about anything with very little setup time. 

With newt you can quickly fuzz:
- Programs with GUIs without the need to modify them
- Command line programs
- Instrumented programs
- Network services

You can also simply use newt to easily monitor a process in the case that you already have a fuzzer in place for an application, and just want a nice way to automatically process crashes. 

newt runs on linux and OSX, and with a little work to setup gdb plays nice with Windows as well. In the future a dedicated windbg monitoring mode may be added. 

## examples
`./newt.js autofuzz -f 32 -s okular -m gdb -i seeds -o out -k 2 -x ripple`
Fuzz okular PDF reader with a fuzz factor of 32, GDB monitoring mode, a two-second kill time and only use the "ripple" mutator mode.

`./newt.js autofuzz -f 48 -s vlc -m asan -i seeds -o out -k 30 -x chunkspew,ripple`
Fuzz VLC player with a fuzz factor of 48, ASAN monitoring mode, a thirty-second kill time and use the "chunkspew" and "ripple" mutator modes.

`./newt.js autofuzz -f 24 -s readelf -m asan -i seeds -o out`
Fuzz the readelf utility with a fuzz factor of 24, ASAN monitoring mode and all available mutators. Note the lack of a kill time as this program will exit on its own after completing its task. 

`cat seed.jpg | ./newt.js mutate -f 16 -x ripple > case.jpg`
Generate a single fuzzed case from an input on stdin, and write the result to stdout using a fuzz factor of 16 and the "ripple" mutator mode.

`./newt.js procmon -s firefox -m gdb -o out -r`
Start firefox and monitor the process using ASAN monitoring mode, and bring the process back up in the event of a crash. Results logged to `out` directory. 

`./newt.js procmon -s objdump case.bin -m asan`
Run a case binary against objdump, log the results to stdout and use the ASAN monitoring mode. Note the lack of the -r restart flag. 

`./newt.js netfuzz -i ngen_seeds -o out -h localhost:1337`
Generate fuzzed requests using ngen templates to the service on port 1337 at localhost. For best results, monitor the server process on the other end using newt's procmon mode. 

A quick tutorial on fuzzing PDF files with newt can be found [here](https://wreet.xyz/2019/03/04/simple-fuzzing-with-newt/).