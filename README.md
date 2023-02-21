CS 61 Problem Set 3
===================

**Fill out both this file and `AUTHORS.md` before submitting.** We grade
anonymously, so put all personally identifying information, including
collaborators, in `AUTHORS.md`.

Grading notes (if any)
----------------------
Hit 's' to try my sleep extra credit
Hit 'm' to try my munmap extra credit (details on both below)


Extra credit attempted (if any)
-------------------------------
I attempted:
 - a sleep syscall. This can put a process to sleep for a specified time period
   and will wake it up again when this timeout expires. You can see this by running p-sleep (make run-sleep, or hit 's').
   In its current configuration, I've set the random seed to 0 and it puts process 4 to sleep for 300 ticks
   before waking it. With this seed you should see process 4 clearly be put to sleep at least once (on the grading server it seems to be put to sleep once,
   on my laptop it gets put to sleep twice but I believe that's due to differing ALLOC_SLOWDOWN) before the physical memory
   fills up, but you can change the constants I defined at the top to see how it behaves.

 - munmap and page_free. These remove pages from maps, and I have a test program p-munmap to demonstrate munmap (make run-munmap, or hit 'm').
   This is less exciting than the last one, it runs until it runs out of memory, and then it munmaps the same three pages forever. I did this
   to show that it behaves as per the requirements of munmap:
    -> Having no allocated pages in the munmapped region is not an error (per the manual), it just does nothing as expected
    -> I gave munmap 3 * PAGESIZE - 2 and it still munmaps 3 full pages, as per  the manual it should unmap any page containing a PART of
       the indicated range are unmapped
    -> You can see the three leaked pages (which we deliberately leak to show munmap worked as intended)

 - Copy on write. I attempted this but removed it as I didn't get it working properly in time for this submission, hoping to submit this later
   when we can submit extra credit later in the semester.
