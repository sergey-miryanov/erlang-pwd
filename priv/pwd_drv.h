#include <pwd.h>
#include <erl_driver.h>
#include <ei.h>
#include <erl_interface.h>

#define CMD_GET_PWUID 1
#define CMD_GET_PWNAM 2
#define CMD_GET_PWALL 3

typedef struct pwd_drv_t {
  ErlDrvPort    port;
  FILE          *log;
} pwd_drv_t;

static ErlDrvData
start (ErlDrvPort port, char *cmd);

static void
stop (ErlDrvData drv);

static int
control (ErlDrvData drv,
  unsigned int command,
  char *buf,
  int len,
  char **rbuf,
  int rlen);

static int
send_error (pwd_drv_t *drv,
  char *tag,
  char *msg);


static int
get_pwuid (pwd_drv_t *drv,
  char *command);

static int
get_pwnam (pwd_drv_t *drv,
  char *command);

static int
get_pwall (pwd_drv_t *drv);

static ErlDrvTermData *
make_passwd (pwd_drv_t *drv,
  struct passwd *pwd, 
  size_t *count);

static void
fill_passwd (ErlDrvTermData *data, struct passwd *pwd,
             char **name,
             char **passwd);

static size_t 
passwd_term_count ();

