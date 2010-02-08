#include "pwd_drv.h"
#include <stdio.h>
#include <string.h>

static ErlDrvEntry driver_entry__ = {
  NULL,                             /* init */
  start,                            /* startup (defined below) */
  stop,                             /* shutdown (defined below) */
  NULL,                             /* output */
  NULL,                             /* ready_input */
  NULL,                             /* ready_output */
  "pwd_drv",                        /* the name of the driver */
  NULL,                             /* finish */
  NULL,                             /* handle */
  control,                          /* control */
  NULL,                             /* timeout */
  NULL,                             /* outputv (defined below) */
  NULL,                             /* ready_async */
  NULL,                             /* flush */
  NULL,                             /* call */
  NULL,                             /* event */
  ERL_DRV_EXTENDED_MARKER,          /* ERL_DRV_EXTENDED_MARKER */
  ERL_DRV_EXTENDED_MAJOR_VERSION,   /* ERL_DRV_EXTENDED_MAJOR_VERSION */
  ERL_DRV_EXTENDED_MAJOR_VERSION,   /* ERL_DRV_EXTENDED_MINOR_VERSION */
  ERL_DRV_FLAG_USE_PORT_LOCKING,    /* ERL_DRV_FLAGs */
  NULL,                             /* handle2 */
  NULL,                             /* process_exit */
  NULL                              /* stop_select */
};

DRIVER_INIT (pwd_driver)
{
  return &driver_entry__;
}

static ErlDrvData
start (ErlDrvPort port, char *cmd)
{
  FILE *log = fopen ("/tmp/erlang-pwd-drv.log", "a+");
  if (!log)
    {
      fprintf (stderr, "Couldn't create log file\n");
      fflush (stderr);
      return (ErlDrvData) -1;
    }

  pwd_drv_t *drv = (pwd_drv_t *)driver_alloc (sizeof (pwd_drv_t));
  if (!drv)
    {
      fprintf (log, "Couldn't allocate memory for driver\n");
      fflush (log);
      fclose (log);

      return (ErlDrvData) -1;
    }

  drv->port = port;
  drv->log  = log;

  fprintf (drv->log, "Start pwd driver\n");
  fflush (drv->log);

  return (ErlDrvData) drv;
}

static void
stop (ErlDrvData p)
{
  pwd_drv_t *drv = (pwd_drv_t *)p;


  fprintf (drv->log, "Stop pwd driver\n");
  fflush (drv->log);
  fclose (drv->log);

  drv->log = 0;

  driver_free (drv);
}

static int
control (ErlDrvData p,
         unsigned int command,
         char *buf,
         int len,
         char **rbuf,
         int rlen)
{
  pwd_drv_t *drv = (pwd_drv_t *)p;
  if (len)
    buf[len] = 0;

  switch (command)
    {
    case CMD_GET_PWUID:
      get_pwuid (drv, buf);
      break;
    case CMD_GET_PWNAM:
      get_pwnam (drv, buf);
      break;
    case CMD_GET_PWALL:
      get_pwall (drv);
      break;
    default:
      send_error (drv, "error", "unknown_command");
      break;
    }

  return 0;
}

static int 
send_error (pwd_drv_t *drv, 
            char *tag,
            char *msg)
{
  ErlDrvTermData spec[] = {
      ERL_DRV_ATOM, driver_mk_atom (tag),
      ERL_DRV_STRING, (ErlDrvTermData)msg, strlen (msg),
      ERL_DRV_TUPLE, 2
  };

  return driver_output_term (drv->port,
                             spec,
                             sizeof (spec) / sizeof (spec[0]));
}

static int
get_pwuid (pwd_drv_t *drv, char *cmd)
{
  __uid_t uid = atoi (cmd);
  struct passwd *pwd = getpwuid (uid);
  if (!pwd)
    {
      fprintf (drv->log, "getpwuid returns NULL for %s\n", cmd);
      fflush (drv->log);

      return send_error (drv, "error", "unknown_uid");
    }

  size_t result_count = 0;
  ErlDrvTermData *result = make_passwd (drv, pwd, &result_count);
  if (!result)
    {
      return send_error (drv, "error", "Couldn't allocate memory");
    }

  int r = driver_output_term (drv->port,
                              result,
                              result_count);

  driver_free (result);
  return r;
}

static int
get_pwnam (pwd_drv_t *drv, char *cmd)
{
  struct passwd *pwd = getpwnam (cmd);
  if (!pwd)
    {
      fprintf (drv->log, "getpwnam returns NULL for %s\n", cmd);
      fflush (drv->log);

      return send_error (drv, "error", "unknown_name");
    }

  size_t result_count = 0;
  ErlDrvTermData *result = make_passwd (drv, pwd, &result_count);
  if (!result)
    {
      return send_error (drv, "error", "Couldn't allocate memory");
    }

  int r = driver_output_term (drv->port,
                              result, 
                              result_count);

  driver_free (result);
  return r;
}

static int
get_pwall (pwd_drv_t *drv)
{
  size_t pwd_count = 0;
  setpwent ();
  while (getpwent ())
    pwd_count++;
  endpwent ();

  size_t term_count = passwd_term_count ();
  size_t result_count = pwd_count * term_count;
  ErlDrvTermData *result = (ErlDrvTermData *) driver_alloc (sizeof (ErlDrvTermData) * (result_count + 3));
  if (!result)
    {
      fprintf (drv->log, "Couldn't allocate memory for result\n");
      fflush (drv->log);

      return send_error (drv, "error", "Couldn't allocate memory for result");
    }

  char **names = (char **) driver_alloc (sizeof (char *) * pwd_count);
  char **pwds  = (char **) driver_alloc (sizeof (char *) * pwd_count);

  setpwent ();

  size_t result_idx = 0;
  struct passwd *pwd = getpwent ();
  while (pwd)
    {
      fill_passwd (&result[result_idx * term_count], pwd, &names[result_idx], &pwds[result_idx]);
      result_idx++;

      pwd = getpwent ();
    }

  endpwent ();

  result[result_count++] = ERL_DRV_NIL;
  result[result_count++] = ERL_DRV_LIST;
  result[result_count++] = pwd_count + 1;

  int r = driver_output_term (drv->port,
                              result,
                              result_count);

  size_t i = 0;
  for (; i < pwd_count; ++i)
    {
      driver_free (pwds[i]);
      driver_free (names[i]);
    }

  driver_free (pwds);
  driver_free (names);
  driver_free (result);
  return r;
}

static ErlDrvTermData *
make_passwd (pwd_drv_t *drv, struct passwd *pwd, size_t *count)
{
  *count = passwd_term_count ();
  ErlDrvTermData *result = (ErlDrvTermData *)driver_alloc (sizeof (ErlDrvTermData) * *count);
  if (!result)
    {
      fprintf (drv->log, "Couldn't allocate memory for result (size: %ld)\n", *count);
      fflush (drv->log);

      *count = 0;
      return 0;
    }

  fill_passwd (result, pwd, 0, 0);
  return result;
}

static void
fill_passwd (ErlDrvTermData *data, struct passwd *pwd,
             char **name,
             char **passwd)
{
  char *pw_name = pwd->pw_name;
  char *pw_passwd = pwd->pw_passwd;

  size_t len_name = strlen (pw_name);
  size_t len_passwd = strlen (pw_passwd);

  if (name)
    {
      *name = (char *) driver_alloc (sizeof (char) * (len_name + 1));
      memcpy (*name, pw_name, sizeof (char) * (len_name + 1));

      pw_name = *name;
    }

  if (passwd)
    {
      *passwd = (char *) driver_alloc (sizeof (char *) * (len_passwd + 1));
      memcpy (*passwd, pw_passwd, sizeof (char) * (len_passwd + 1));

      pw_passwd = *passwd;
    }

  *data++ = ERL_DRV_ATOM;
  *data++ = driver_mk_atom ("pw_name");
  *data++ = ERL_DRV_STRING;
  *data++ = (ErlDrvTermData) pw_name;
  *data++ = strlen (pwd->pw_name);
  *data++ = ERL_DRV_TUPLE;
  *data++ = 2;

  *data++ = ERL_DRV_ATOM;
  *data++ = driver_mk_atom ("pw_passwd");
  *data++ = ERL_DRV_STRING;
  *data++ = (ErlDrvTermData) pw_passwd;
  *data++ = strlen (pwd->pw_name);
  *data++ = ERL_DRV_TUPLE;
  *data++ = 2;

  *data++ = ERL_DRV_ATOM;
  *data++ = driver_mk_atom ("pw_uid");
  *data++ = ERL_DRV_UINT;
  *data++ = pwd->pw_uid;
  *data++ = ERL_DRV_TUPLE;
  *data++ = 2;

  *data++ = ERL_DRV_ATOM;
  *data++ = driver_mk_atom ("pw_gid");
  *data++ = ERL_DRV_UINT;
  *data++ = pwd->pw_gid;
  *data++ = ERL_DRV_TUPLE;
  *data++ = 2;
  
  *data++ = ERL_DRV_TUPLE;
  *data++ = 4;
}

static size_t 
passwd_term_count ()
{
  return 2 + 3 + 2 +  // username tuple
         2 + 3 + 2 +  // password tuple
         2 + 2 + 2 +  // uid tuple
         2 + 2 + 2 +  // gid tuple
         2;         // total tuple
}
