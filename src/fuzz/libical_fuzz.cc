#include <string.h>
#include <stdint.h>
#include "libical/ical.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return 0;
  char *str = new char[size+1];
  memcpy(str, data, size);
  str[size] = 0;
  icalcomponent* component;

  component = icalparser_parse_string(str);

  if (component != 0) {
    icalcomponent_free(component);
  }

  delete [] str;
  return 0;
}
