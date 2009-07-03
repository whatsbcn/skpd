#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void die(const char* message) {
  puts(message);
  exit(1);
}

int main() {
  char buf[100]="fnord";
  char buf2[100]="fnort";
  if (strcmp(buf,buf)) die("strcmp say a != a");
  if (strcmp(buf,buf2)>=0) die("strcmp said fnord > fnort");
  if (strcmp(buf2,buf)<=0) die("strcmp said fnort < fnord");
  if (strcmp(buf+1,buf2+1)>=0) die("unaligned strcmp is broken");
  if (strcmp(buf+2,buf2+2)>=0) die("unaligned strcmp is broken");
  if (strcmp(buf+3,buf2+3)>=0) die("unaligned strcmp is broken");
  return 0;
}
