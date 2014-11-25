atch
====

a little tool to manage scripts, particularly for configuration purposes. under development. works by maintaining a tree of hash tables containing metadata about scripts (supplied with special annotation on the scripts themselves). the structure of the tree corresponds to the directory structure of the 'scripts' directory, and then at runtime, the command line arguments are used to drill into this tree and intelligently invoke a script or command stored at any node, after making the appropriate subsitutions. also has support for 'hooking' a script up to another, so when the latter is invoked, the hooked-on script will be invoked before or after.
