# CSE331-Project2
CSE331 Project #2 - Stack Smashing and Format String Attacks

## Authd Exploit (Data-only attack) (driver_authd.c)
For the values used for calculating differences, we used `gdb` to read the values of the `ebp` and `eip` registers. To get the values of the main loop and auth ra, we called the functions and used gdb to print the registers.

We used `gdb` to print the `auth_user` and `g_authd` variables to populate those values.

To locate the canary, we used `gdb` to print the contents of the stack. Using the pointers to the previous frame and the return address, we were able to approximate the location of the canary. We searched for values that did not conform to the other values on the stack, since the canary is a random value and appears differently from the majority of the rest of the values on the stack. We were able to isolate two possible locations for the canary location, and tried them both until finding the one that worked.

To populate the `auth_ra_loc` value, we used `gdb` to print out the contents of the stack. Since we had previously found the value of `auth_ra`, we looked for the location of that value and stored that value in `auth_ra_loc`. We used a similar strategy to populate the `auth_bp_loc` value.

To find the offset values for the `put_str` command, we first wrote a Python script to print the values stored at each of the offset values from 500 to 600, using the values in the example as a reference. We found the offset for `cur_mainloop_ra` by looking for the `mainloop_ra` value we had found previously. We found the `cur_mainloop_bp` value by using `gdb`'s `info frame` function to get the current edp value, and added `0x30`. This addition was based on examination of the example exploit. To find the canary value (`cur_canary`), we looked for a random number that was in proximity to the other 2 values. This approach was based on the sample exploit, since the offsets in that exploit were all relatively close to each other.

## We did not perform any other attacks.

