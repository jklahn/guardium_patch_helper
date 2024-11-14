## RPMs installation

Any RPM file within this folder will be installed when the application is installed to a docker using 

`grd_sdk run -d -w appFolder`


Add _ordering.txt_ to this folder only if you need ordered installation of RPMs, when you have dependent RPMs. For example, _ordering.txt_ may contain

> first-install-this-rpm.rpm   
then-jre-8u151-linux-x64.rpm
