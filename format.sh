# Small script that removes trailing whitespace from files in the repository
#!/bin/sh

find .[a-z]* * -type f -print0 | grep -zZv '^.git/' | xargs -0 perl -pi -e 's/[ \t]+$//'
