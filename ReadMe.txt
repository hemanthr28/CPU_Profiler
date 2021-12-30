This is a Linux user space module that gets the 20 most scheduled process and stores in a RB tree. 

To insert the module:
sudo insmod perftop.ko 

To view the results:
cat /proc/perftop 

To remove the module:
sudo rmmod perftop.ko
