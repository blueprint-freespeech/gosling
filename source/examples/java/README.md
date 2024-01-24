# Java Example

To build and run, you will need `Gosling.jar` and `libgoslingjni.so`

## Build:

`javac -cp /path/to/Gosling.jar Example.java`

## Run

`java -cp classes:.:/path/to/Gosling.jar -Djava.library.path=/path/to/libgoslingjni.so Example`