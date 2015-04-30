#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "icalcap.h"
#include "icalcap_impl.h"
#include "icalcap_session_impl.h"       /* FIXME */

#include <stdlib.h>

void
icalcap_free(icalcap *cap) {

#ifdef WITH_RR
        icalcap_free_rr(cap);
#endif
}

int
icalcap_stop(icalcap *cap) {

#ifdef WITH_RR
        return icalcap_stop_rr(cap);
#else
        return 0;
#endif
}

const char *
icalcap_get_username(const icalcap *cap) {

#ifdef WITH_RR
        if (cap == NULL || cap->username == NULL)
                return NULL;

        return cap->username;
#else
        return NULL;
#endif
}
