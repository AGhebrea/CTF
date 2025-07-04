# Description
The executable is linked with a custom libc and you don't have access to it. The idea is to use the arbitrary read primitive to leak the ELF structures and get RCE. 
./cyberedu/writeup/writeup.md contains additional information.
./cyberedu/writeup/solution.py is the solution script.

# Deploy + run solution.
```
cd cyberedu/deploy
docker-compose up &
cd ../writeup/
python solution.py
```

# Building the source 
For building you have to set GLIBCDIR to a directory where glibc is installed, for example on a normal linux distro the path would be /usr
```
cd cyberedu/src/
make
```