/*
 * Copyright (c) 2014 Jay Schulist <jayschulist@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 3, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranties of
 * MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif

#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>

enum prompts {
  BTC_ADDR,
  BTC_MSG2SIGN,
  BTC_SIG
};

static char *
get_bitcoin_info(pam_handle_t * pamh, int type)
{
  struct pam_message message;
  const struct pam_message * pmessage = &message;
  char *msg = NULL;
  int len;

  /* build up the message we're prompting for */
  message.msg = NULL;
  message.msg_style = PAM_PROMPT_ECHO_ON;

  switch (type) {
    case BTC_ADDR:
      message.msg = "bitcoin: ";
      break;

    case BTC_MSG2SIGN:
      message.msg = "message: ";
      break;

    case BTC_SIG:
      message.msg = "signature: ";
      break;
  }

  struct pam_conv *conv = NULL;
  if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS || conv == NULL || conv->conv == NULL) {
    return NULL;
  }

  struct pam_response *responses = NULL;
  if (conv->conv(1, &pmessage, &responses, conv->appdata_ptr) != PAM_SUCCESS || responses == NULL) {
    return NULL;
  }

  char * promptval = responses->resp;
  free(responses);

  /* If we didn't get anything, just move on */
  if (promptval == NULL) {
    return NULL;
  }

  msg = malloc(PAM_MAX_MSG_SIZE);
  memset(msg, '\0', PAM_MAX_MSG_SIZE);
  len = strlen(promptval);
  if (len > PAM_MAX_MSG_SIZE)
    len = PAM_MAX_MSG_SIZE;
  memcpy(msg, promptval, len);

  // printf("%s\n", promptval);
  free(promptval);
  return msg;
}

/* changing authentication token, could be used to update what bitcoin address
 * allowed to login from?
 */

static int
pam_bitcoin (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  char msg[PAM_MAX_MSG_SIZE];
  int orig_argc = argc;
  const char **orig_argv = argv;
  const char *file = NULL;
  char *message = NULL;
  char *addr = NULL;
  char *sig = NULL;
  char username[PAM_MAX_MSG_SIZE];
  int fd, retval;

  /* use filename for bitcoin username lookup. */
  for (; argc-- > 0; ++argv) {
      if (!strncmp (*argv, "file=", 5))
	file = (5 + *argv);
  }

  /* No file= option, must have it.  */
  if (file == NULL || file[0] == '\0') {
    pam_syslog(pamh, LOG_ERR, "Bitcoin login allowed users configuration file not provided");
    retval = PAM_IGNORE;
    return retval;
  }

  /* If no configuration then ignore, so defaults work. */
  fd = open(file, O_RDONLY);
  if (fd < 0) {
    pam_syslog(pamh, LOG_ERR, "Unable to open configuration file: %s", file);
    retval = PAM_IGNORE;
    return retval;
  }

  /* get bitcoin address. */
  if ((addr = get_bitcoin_info(pamh, BTC_ADDR)) == NULL) {
    retval = PAM_AUTH_ERR;
    return retval;
  }
  // printf("will use address: %s\n", addr);

  /* validate address format? Who cares if it has to be in a file... */

  /* lookup address to see if user can login using bitcoin. */
  strcpy(username, "btctest");
  close(fd);

  /* option for bitid challenge generation.
   *
   * bitid://hostname/callback?x=Nonce&u=1 
   *
   * show QR code to sign with mobile device
   */

  /* get message to sign. */
  if ((message = get_bitcoin_info(pamh, BTC_MSG2SIGN)) == NULL) {
    retval = PAM_AUTH_ERR;
    return retval;
  }
  // printf("will sign message: %s\n", message);

  /* get signature of message. */
  if ((sig = get_bitcoin_info(pamh, BTC_SIG)) == NULL) {
    retval = PAM_AUTH_ERR;
    return retval;
  }
  // printf("will use signature: %s\n", sig);

  /* use signature to authenticate address. */
 
  /* get username details associated with this address. */
  retval = pam_set_item(pamh, PAM_USER, username);
  if (retval != PAM_SUCCESS) {
    printf("set pam_user failed\n");
    return PAM_USER_UNKNOWN;
  }

  /* do bitid callback for pam... */

  pam_syslog(pamh, LOG_INFO, "bitcoin authentication successful: %s (%s)", addr, username);

  free(addr);
  free(message);
  free(sig);

  retval = PAM_SUCCESS;
  return retval;
}

int
pam_sm_authenticate (pam_handle_t *pamh, int flags, int argc,
                     const char **argv)
{
  return pam_bitcoin (pamh, flags, argc, argv);
}

int
pam_sm_setcred (pam_handle_t *pamh, int flags,
		int argc, const char **argv)
{
  return PAM_IGNORE;
}

int
pam_sm_acct_mgmt (pam_handle_t *pamh, int flags, int argc,
		  const char **argv)
{
  return PAM_IGNORE;
}

int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc,
		     const char **argv)
{
  return PAM_IGNORE;
}

int
pam_sm_close_session (pam_handle_t *pamh, int flags,
		      int argc, const char **argv)
{
  return PAM_IGNORE;
}

int
pam_sm_chauthtok (pam_handle_t *pamh, int flags, int argc,
		  const char **argv)
{
    return PAM_IGNORE;
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_bitcoin_modstruct = {
  "pam_bitid",
  pam_sm_authenticate,
  pam_sm_setcred,
  pam_sm_acct_mgmt,
  pam_sm_open_session,
  pam_sm_close_session,
  pam_sm_chauthtok,
};

#endif
