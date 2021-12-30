## [M1: point 1]
#  Defining the module name as ex3 (updated from ex333 to ex3)
#  ...
CONFIG_MODULE_SIG=n
MODULE = perftop

## [M2: point 1]
#  To indicate the kernel to build ex3.o from the ex3.c file
#  ...
obj-m += $(MODULE).o

## [M3: point 1]
#  Gets the path of the linux kernel's build directory
#  ...
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

## [M4: point 1]
#  This invokes the shell to execute pwd command and we 
#  get the current working directory
#  ...
PWD := $(shell pwd)

## [M5: point 1]
#  This builds all the files indicated by MODULE, here ex3
#  ...
all: $(MODULE)

## [M6: point 1]
#  %.o: %.c specifies all the files ending with .o must have the 
#  corresponding .c file to be present. 
#  And the wild card includes all the prerequisite filenames required for the build
#  ...
%.o: %.c
	@echo "  CC      $<"
	@$(CC) -c $< -o $@

## [M7: point 1]
#  This causes the invocation of make recursively in the provided directories 
#  ...
$(MODULE):
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

## [M8: point 1]
#  This command will be used to clean recursively in all the directories mentioned 
#  ...
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
