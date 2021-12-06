# CSE331-Project2
CSE331 Project #2 - Stack Smashing and Format String Attacks


For the top4 , used gdb to read the values of the ebp and eip.  To get the values of the main and auth ra, we had to call them and then run gdp to read the register's values.

user_varible: In gdb, printing user_variable helps you get this value.

canary: Is a random value every time, so we printed out the stack each time.  Using the old fp and ra pointer, I knew the canary had to be between (around) them.  Using gdb,I searched values near the fp and ra looking for values that looked random (not uniform) since the stack overall looks uniform.  Using this informal strategy, I narrowed down 2 possibilities and after trying both.  One worked.

auth_ra_loc: Printed out the stack looking for the virtual address auth_ra.  After finding it, I recorded it in auth_ra_loc

auth_bp_loc: Used a similar strategy as with searching for auth_ra_loc.

g_authd_: In gdb, printing authd helped me trace this value.

Finding the offset values in put_str( val1 val2 val3 ): Wrote a bruteforce python script to print every value from off 500 to off 600.
And then matched these values with the number written down earlier.



