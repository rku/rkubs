/**
 * Battleships Game
 * http://tocix.bitkanal.net/software/rkubs/
 *
 * Compile the game as follows: (tested with: linux, cygwin, macosx)
 * Please note: openssl is required for cheat protection
 *
 * gcc -o rkubs rkubs.c -DWITH_ANSI_ESCAPE_SEQ -lcrypto
 *
 * Copyright (C) 2006-2007  Rene Kuettner, <rene@bitkanal.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/sha.h>

#define RKUBS_VERSION       "0.4"
#define RKUBS_NET_VERSION_N (uint8_t)5
#define BFIELD_SIZEY        9
#define BFIELD_SIZEX        BFIELD_SIZEY
#define NAME_MAXLEN         16
#define TRUE                1
#define FALSE               0
#define DEFAULT_PORT        42339
#define BANNER              "RKUs Battleship Game"

#define _err(x) if(x) { fprintf(stderr,\
    "\n%s:%d %s() %s (%d)\n",__FILE__,__LINE__,__func__,\
    strerror(errno),errno); exit(-1); }

typedef int bool;
typedef unsigned char hash_t[SHA_DIGEST_LENGTH];
typedef unsigned char hmac_key[64];

/* a battlefield */
typedef struct _battlefield {
  char field[BFIELD_SIZEY][BFIELD_SIZEX];
  char player_name[NAME_MAXLEN];
  uint8_t hits;
  hmac_key key;
} battlefield;

/* the game session */
typedef struct _game_session {
  battlefield field_a;
  battlefield field_b;
  char name[NAME_MAXLEN];
  struct sockaddr_in opponent_addr;
  int sock;
  unsigned int port;
  hash_t local_hash;
  hash_t opponent_hash;
} game_session;

game_session session;

/* network message types */
#define MSG_TYPE_REQUEST_GAMES  0x00
#define MSG_TYPE_GAME_ANNOUNCE  0x01
#define MSG_TYPE_GAME_JOIN      0x02
#define MSG_TYPE_GAME_JOINED    0x03
#define MSG_TYPE_GAME_QUIT      0x04
#define MSG_TYPE_CHAT           0x05
#define MSG_TYPE_READY          0x06
#define MSG_TYPE_GAME_ATTACK    0x07
#define MSG_TYPE_GAME_HIT       0x08
#define MSG_TYPE_GAME_FAILED    0x09
#define MSG_TYPE_GAME_FINISHED  0x0a

/* attack types (only normal attacks at the moment) */
#define ATTACK_TYPE_NORMAL      0x00

/* ansi escape sequences (color support) */
#ifdef WITH_ANSI_ESCAPE_SEQ
#define ANSIESC_RESET           "\033[m"
#define ANSIESC_RED             "\033[1;31m"
#define ANSIESC_BLUE            "\033[1;34m"
#define ANSIESC_GREEN           "\033[1;32m"
#define ANSIESC_YELLOW          "\033[1;33m"
#define ANSIESC_GREY            "\033[1;30m"
#define ANSIESC_CURSORNN        "\033[0;0H"
#define ANSIESC_CLEARSCR        "\033[2J"
#endif

/* coordinate */
typedef struct _coords {
  uint8_t x;
  uint8_t y;
} coords;

/* a ship */
typedef struct _ship {
  const unsigned int size;
  unsigned char direction;
  coords position;
} ship;

/* the structure of network packages */
typedef struct _net_msg {
  uint8_t msg_version;
  uint8_t msg_type;
  uint8_t attack_type;
  coords point;
  char game_name[NAME_MAXLEN];
  char player_name[NAME_MAXLEN];
  char data[128];
  battlefield field;
} net_msg;

/* ship setup */
#define SHIP_COUNT              3
#define SHIP_PIECES             12
#define SHIP_DIRECTION_H        0x00
#define SHIP_DIRECTION_V        0x01
#define SHIP_DIRECTION_DU       0x02
#define SHIP_DIRECTION_DD       0x03
ship ships[SHIP_COUNT] = {
  {2, SHIP_DIRECTION_H, {0,0}},
  {4, SHIP_DIRECTION_H, {0,0}},
  {6, SHIP_DIRECTION_H, {0,0}}
};

/* host/client indicator */
bool create_game = TRUE;

/* prototypes */
void set_name(char*,battlefield*);
void init_net(game_session*);
void init_fields(game_session*);
void print_fields(game_session*,bool);
void print_field_row(battlefield*,int);
void clear_input_buffer(void);
void read_input(char*, size_t, char*, ...);
int  read_choice(char*, size_t, char*, ...);
void set_new_game(game_session*);
void join_game(game_session*);
void game(game_session*);
void set_ships_manual(game_session*);
void set_ships_random(game_session*);
bool set_ship(game_session*, int);
void send_chat_msg(game_session*, char*);
bool attack(game_session*, battlefield*, net_msg*);
bool process_attack_response(game_session*, net_msg*);
int  net_write(game_session*, net_msg*);
int  net_read(game_session*, net_msg*);
void finish(game_session*);
void get_randomdev_data(void*, size_t);
void hmac_battlefield(battlefield *, hash_t*);

/** parse command line and set up the game as client or server **/
int main(int argc, char **argv)
{
  struct passwd *pwd;
  struct hostent *he;
  int    opt;
  char   *p = strrchr(argv[0], '/');

  init_net(&session);
  setvbuf(stdin, NULL, _IONBF, 0);

  printf("%s v%s\n", BANNER, RKUBS_VERSION);

  pwd =getpwuid(getuid());
  set_name(pwd->pw_name, (battlefield*)&session.field_a);

  while((opt=getopt(argc,argv,"hp:n:"))!=-1)
  {
    switch(opt)
    {
      case 'p':
        session.port = (unsigned int)strtol(optarg,NULL,10);
        if(session.port<1 || session.port > 65535)
        {
          fprintf(stderr,"invalid port number\n");
          exit(-1);
        }
        break;
      case 'n':
        set_name(optarg, (battlefield*)&session.field_a);
        break;
      case '?':
      case 'h':
	if(p++ == NULL) p = argv[0];
        printf("%s [-h] [-p <port>] [-n <name>] [<host>]\n\n", p);
        printf("-h          print usage\n");
        printf("-p <port>   set tcp port\n");
        printf("-n <name>   your name (defaults to username)\n");
        printf("<host>      Join game hosted by <host>\n\n");
        exit(0);
    }
  }

  if(argc>optind)
  {
    create_game = FALSE;
 
    he = gethostbyname(argv[optind]);
    if(he==NULL)
    {
      herror("gethostbyname");
      exit(-1);
    }

    session.opponent_addr.sin_family = PF_INET;
    session.opponent_addr.sin_port = htons(session.port);
    memcpy(&session.opponent_addr.sin_addr.s_addr,
    he->h_addr_list[0], he->h_length);
  }

  if(create_game)
  {
    set_new_game(&session);
  }
  else
  {
    join_game(&session);
  }

  game(&session);

  return(0);
}

/** set the player name of a battlefield **/
void set_name(char *name, battlefield *f)
{
  strncpy(f->player_name, name, NAME_MAXLEN-1);
}

/** initialize network **/
void init_net(game_session *g)
{
  const int o = 1;

  g->sock = socket(PF_INET, SOCK_STREAM, 0);
  _err(g->sock==-1);

  g->port = DEFAULT_PORT;

  setsockopt(g->sock, SOL_SOCKET, SO_REUSEADDR, &o, sizeof(o));
#ifdef SO_REUSEPORT
  setsockopt(g->sock, SOL_SOCKET, SO_REUSEPORT, &o, sizeof(o));
#endif
}

/** initialize battlefields **/
void init_fields(game_session *g)
{
  int r,c;

  for(r=0;r<BFIELD_SIZEY;r++)
  for(c=0;c<BFIELD_SIZEX;c++)
  {
    g->field_a.field[r][c] = '~';
    g->field_b.field[r][c] = '?';
  }

  g->field_a.hits = 0;
  g->field_b.hits = 0;
}

/** print both battlefields to screen **/
void print_fields(game_session *g, bool both)
{
  int r;

  printf("\n");

  for(r = -2; r < BFIELD_SIZEY; r++)
  {
    print_field_row(&g->field_a, r);

    if(both)
    {
      printf("  |  ");
      print_field_row(&g->field_b, r);
    }

    printf("\n");
  }

  printf("\n");

  if(both)
  {
    printf("  ++ You: %i/%i hits\n", g->field_b.hits, SHIP_PIECES);
    printf("  ++ %s: %i/%i hits\n\n", g->field_b.player_name,
      g->field_a.hits, SHIP_PIECES);
  }
}

/** print a battlefield row to the screen **/
void print_field_row(battlefield *f, int row)
{
  int c;

  for(c = 0; c < BFIELD_SIZEX; c++)
  {
    if(!c) printf("%c%c",
      (row > -1) ? 'A' + row : ' ',
      (row > -1) ? '|' : (row == -1) ? '+' : ' ');
    if(row < 0) 
    {
      if(row == -2) printf(" %i ", c + 1);
      if(row == -1) printf("---");
    }
    else
    {
      char ch = f->field[row][c];
#ifdef WITH_ANSI_ESCAPE_SEQ
      if(ch == '~')   printf("%s", ANSIESC_BLUE);
      if(ch == 'X')   printf("%s", ANSIESC_RED);
      if(isdigit(ch)) printf("%s", ANSIESC_GREEN);
      if(ch == '?')   printf("%s", ANSIESC_GREY);
#endif
      printf(" %c ", ch);
#ifdef WITH_ANSI_ESCAPE_SEQ
      printf("%s", ANSIESC_RESET);
#endif
    }
  }
}

/** clear the input buffer (keyboard input) **/
void clear_input_buffer(void)
{
  struct timeval tv;
  fd_set fds;
  char   buf;

  tv.tv_usec = 0;
  tv.tv_sec = 0;
 
  FD_ZERO(&fds);
  FD_SET(fileno(stdin), &fds);

  fflush(stdin);
  while(select(1, &fds, NULL, NULL, &tv) != 0) read(fileno(stdin), &buf, 1);
}

/** read an input line from buf **/
void read_input(char *buf, size_t blen, char *prompt, ...)
{
  char    *p;
  va_list va;

  clear_input_buffer();
  if(prompt != NULL)
  {
    va_start(va, prompt);
    vprintf(prompt, va);
    printf("> ");
    va_end(va);
    fflush(stdout);
  }

  bzero(buf, blen);
  fgets(buf, blen, stdin);

  if((p = strrchr(buf,'\n')) != NULL) *p = '\0';
}

/** read a choice from stdin,
 ** choices is an array of possible choices and count the ammount
 ** of choices in this array **/
int read_choice( char *choices, size_t count, char *prompt, ...)
{
  char    c;
  int     i;
  va_list va;

  while(1)
  {
    clear_input_buffer();
    va_start(va, prompt);
    vprintf(prompt, va);
    va_end(va);
    printf(" (");

    for(i = 0; i < count; i++)
    {
      if(i == 0)
      {
        printf("[%c]", choices[i]);
      }
      else
      {
        printf(", %c", choices[i]);
      }
    }

    printf(")? ");
    fflush(stdout);

    c = fgetc(stdin);
    if(c == '\n') return(TRUE);

    c = tolower(c);
    for(i = 0; i < count; i++)
      if(c == tolower(choices[i])) return(tolower(choices[i]));

    printf("*** Invalid choice\n");
  }
}

/** host a new game **/
void set_new_game(game_session *g)
{
  char         game_name[NAME_MAXLEN];
  unsigned int sin_len;
  unsigned int rs = 0;
  struct       sockaddr_in sin;
  net_msg      msg;
  int          new_sock = 0;
    
  snprintf((char*)&game_name, NAME_MAXLEN,
    "%s's game", g->field_a.player_name);

  printf("*** Hosting game \"%s\".\n", game_name);
  printf("*** Waiting for opponent (^C to abort)...... ");
  fflush(stdout);
 
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons(g->port);
  sin.sin_family = PF_INET;
  sin_len = sizeof(sin);

  _err(bind(g->sock, (struct sockaddr*)&sin, sin_len) != 0);
  _err(listen(g->sock,10) != 0);

  while(rs != sizeof(msg) ||
    msg.msg_version!=RKUBS_NET_VERSION_N ||
    msg.msg_type!=MSG_TYPE_GAME_JOIN)
  {
    _err((new_sock = accept(g->sock,(struct sockaddr*)&g->opponent_addr,
      &sin_len))<0);
    _err((rs = recv(new_sock, &msg, sizeof(msg),0))<0);
  }

  close(g->sock);
  g->sock = new_sock;
  printf("\n*** %s has joined the game.\n", msg.player_name);

  set_name(msg.player_name, &g->field_b);
  msg.msg_type = MSG_TYPE_GAME_JOINED;
  strncpy(msg.player_name, g->field_a.player_name, NAME_MAXLEN - 1);
  net_write(g, &msg);
}

/** join a game (client) **/
void join_game(game_session *g)
{
  net_msg msg;

  printf("*** Connecting to game at %s....",
  inet_ntoa(g->opponent_addr.sin_addr));
  fflush(stdout);

  int sin_len = sizeof(g->opponent_addr);
  _err(connect(g->sock, (struct sockaddr*)&g->opponent_addr, sin_len) != 0);

  printf("Connected!\n*** Joining the game...");
  fflush(stdout);

  msg.msg_version = RKUBS_NET_VERSION_N;
  msg.msg_type = MSG_TYPE_GAME_JOIN;
  strncpy(msg.player_name, g->field_a.player_name, NAME_MAXLEN - 1);

  net_write(g, &msg);

  while(1)
  {
    net_read(g, &msg);
    if(msg.msg_type == MSG_TYPE_GAME_JOINED) break;
    fprintf(stderr,"\n+++ invalid paket received (not a game connection?)");
  }

  set_name(msg.player_name, &g->field_b);
  printf("ok\n");
}

/** the main game routine **/
void game(game_session *g)
{
  bool    wait_for_opponent = (!create_game);
  net_msg msg;

  do
  {
    init_fields(g);
    if(read_choice("yn", 2, "Set ships manually?")=='y')
    {
      set_ships_manual(g);
    }
    else
    {
      set_ships_random(g);
    }
  } while(read_choice("yn", 2, "Ship setup okay?") != 'y');

  get_randomdev_data(&g->field_a.key, sizeof(g->field_a.key));
  hmac_battlefield(&g->field_a, &g->local_hash);

  msg.msg_type = MSG_TYPE_READY;
  msg.msg_version = RKUBS_NET_VERSION_N;
  memcpy(&msg.data, &g->local_hash, sizeof(g->local_hash));
  net_write(g, &msg);

  do
  {
    printf("*** Waiting for opponents ships...");
    fflush(stdout);

    net_read(g, &msg);
    if(msg.msg_type == MSG_TYPE_READY)
    {
      memcpy(g->opponent_hash, &msg.data, sizeof(g->opponent_hash));
      break;
    }

  } while(1);

  printf("game started. Good luck!\n");
  print_fields(g,TRUE);

  do
  {
    char buf[256];
    char *p = (char*)&buf;

    if(wait_for_opponent)
    {
      printf("*** Waiting for %s's attack...", g->field_b.player_name);
      fflush(stdout);

      while(1)
      {
        net_read(g, &msg);
        if(msg.msg_type == MSG_TYPE_GAME_ATTACK)
        {
          if(attack(g, &g->field_a, &msg))
          {
            printf("\n*** %s HITS YOU!\n",
            g->field_b.player_name);
            msg.msg_type = MSG_TYPE_GAME_HIT;
          }
	  else
	  {
            printf("\n*** %s failed at %c%i!\n",
              g->field_b.player_name,
              'A' + msg.point.y,
              msg.point.x + 1);
              msg.msg_type = MSG_TYPE_GAME_FAILED;
          }

          net_write(g,&msg);
          sleep(1);
          print_fields(g,TRUE);

          break;
        }

        if(msg.msg_type == MSG_TYPE_GAME_QUIT)
        {
          printf("\n*** %s has left the game.\n",
            g->field_b.player_name);
          exit(1);
        }

        /*if(msg.msg_type == MSG_TYPE_CHAT)
          {
            printf("\n--- <%s> %s\n", msg.player_name, msg.data);
            continue;
          }*/

        fprintf(stderr, "Invalid message type received!\n");
      }
    }
 
    if(g->field_a.hits >= SHIP_PIECES) finish(g);

    wait_for_opponent = FALSE;
    read_input((char*)&buf, sizeof(buf), "your attack (? for help)");

    if(strlen(p) && *p == '?')
    {
      printf("*** You can enter the coordinate of your attack.\n");
      printf("*** (Examples: A5, D6, ..)\n");
      printf("*** Type 'quit' to abort the game.\n");
      //printf("* You can send a chat message by typing /<message>\n");
      continue;
    }

    if(!strncasecmp(p, "quit", 5))
    {
      msg.msg_type = MSG_TYPE_GAME_QUIT;
      net_write(g, &msg);
      printf("\nYou left the game.\n");
      exit(1);
    }

    /*if(strlen(p > 1) && *p == '/')
      {
        send_chat_msg(g, p + 1);
        continue;
      }*/

    if(strlen(p) == 2 &&
      (isdigit(*p) || isdigit(p[1])) &&
      (isalpha(*p) || isalpha(p[1])))
    {
      coords point;

      point.x = (uint8_t)(isdigit(*p)) ? *p - '1' : *(p + 1) - '1';
      point.y = (uint8_t)(isdigit(*p)) ?
        toupper(*(p + 1)) - 'A' : toupper(*p) - 'A';

      if(point.x >= BFIELD_SIZEX || point.y >= BFIELD_SIZEY)
      {
        printf("*** Invalid coordinate. (Example: A5, D3, ...)\n");
        continue;
      }

      if(g->field_b.field[point.y][point.x] != '?')
      {
        printf("*** You've already shot this area.\n");
        continue;
      }

      msg.msg_version = RKUBS_NET_VERSION_N;
      msg.msg_type = MSG_TYPE_GAME_ATTACK;
      msg.attack_type = ATTACK_TYPE_NORMAL;
      msg.point = point;
      strncpy(msg.player_name, g->field_a.player_name, NAME_MAXLEN - 1);

      printf("\n*** Attacking enemy at %c%i...", 'A' + point.y, point.x + 1);
      fflush(stdout);

      net_write(g, &msg);
      wait_for_opponent = TRUE;

      while(1)
      {
        net_read(g, &msg);
        if(process_attack_response(g, &msg)) break;
      }

      sleep(1);
      print_fields(g,TRUE);

      if(g->field_b.hits >= SHIP_PIECES) finish(g);
      continue;
    }

    printf("!!! invalid input ('%s'), type '?' for help\n", p);

  } while(1);
}

/** manual ship setup by the user **/
void set_ships_manual(game_session *g)
{
  int i;

  for(i = 0; i < SHIP_COUNT; i++)
  {
    char buf[256];
    char *p = (char*)&buf;

    print_fields(g, FALSE);

    do
    {
      read_input((char*)&buf, sizeof(buf),
        "Ship (%i, Size %i) Position (e.g.: A5, B5)",
        i + 1, ships[i].size);
      if(strlen(p) == 2 && (isdigit(*p) || isdigit(*(p + 1))) &&
        (isalpha(*p) || isalpha(*(p + 1))))
      {
        ships[i].position.x = (int)(isdigit(*p)) ? *p - '1' : *(p + 1) - '1';
        ships[i].position.y = (int)(isdigit(*p)) ?
	  toupper(*(p + 1)) - 'A' : toupper(*p) - 'A';
        break;
      }
      else
      {
        printf("*** Please enter a coordinate!\n");
      }
    } while(1);

    printf("*** Set direction (h=horizontal, v=vertical, d=diagonal)\n");
    switch((read_choice("hvd", 3, "Direction")))
    {
      case 'v':
        ships[i].direction = SHIP_DIRECTION_V;
        break;
      case 'd':
        switch(read_choice("ud", 2, "Diagonal up or down"))
        {
          case 'u':
            ships[i].direction = SHIP_DIRECTION_DU;
            break;
          case 'd':
          default:
            ships[i].direction = SHIP_DIRECTION_DD;
            break;
        }
        break;
      case 'h':
      default:
        ships[i].direction = SHIP_DIRECTION_H;
        break;
    }

    if(!set_ship(g, i))
    {
      printf("*** Cannot set ship there!\n");
      i--;
    }
    else
    {
      printf("*** Ship %i set.\n", i + 1);
    }

    sleep(1);
  }

  print_fields(g, FALSE);

}

/** set random ships **/
void set_ships_random(game_session *g)
{
  int           i;
  unsigned long seed;

  printf("*** Calculating random ship positions...\n");
  fflush(stdout);

  get_randomdev_data(&seed,sizeof(seed));
  srandom(seed);

  for(i = 0; i < SHIP_COUNT; i++)
  {
    int x;
    int y;
    int d;

    while(1)
    {    
      x = (int) random() % BFIELD_SIZEX;
      y = (int) random() % BFIELD_SIZEY;
      d = (int) random() % 4;

      ships[i].direction = d;
      ships[i].position.x = x;
      ships[i].position.y = y;

      if(set_ship(g, i)) break;
    }            
  }

  print_fields(g, FALSE);
}

/** set a ship, si ist the ship size (1 to n) **/
bool set_ship(game_session *g, int si)
{
  battlefield tmpf;
  int         i;
  ship        s = ships[si];
  int         x = s.position.x;
  int         y = s.position.y;

  tmpf = g->field_a;
  for(i = 0; i < s.size; i++)
  {
    if(x < 0 || y < 0 || x >= BFIELD_SIZEX || y >= BFIELD_SIZEY)
      return(FALSE);
    if(isdigit(g->field_a.field[y][x]))
      return(FALSE);
 
    tmpf.field[y][x] = '1' + si;
 
    switch(s.direction)
    {
      case SHIP_DIRECTION_DU:
        x++;
        y--;
        break;
      case SHIP_DIRECTION_DD:
        x++;
	y++;
        break;
      case SHIP_DIRECTION_H:
        x++;
        break;
      case SHIP_DIRECTION_V:
      default:
        y++;
        break;
    }
  }

  g->field_a = tmpf;

  return(TRUE);
}

/** send a chat message **/
void send_chat_msg(game_session *g, char *s)
{
  net_msg msg;

  msg.msg_type = MSG_TYPE_CHAT;
  strncpy((char*)&msg.data, s, strlen(s));
  net_write(g, &msg);
}

/** process an attack **/
bool attack(game_session *g, battlefield *field, net_msg *msg)
{
  int  x = msg->point.x;
  int  y = msg->point.y;

  if(x >= (BFIELD_SIZEX) || y >= BFIELD_SIZEY || x < 0 || y < 0)
  {
    printf("\n+++ malformed attack (%i,%i)\n", x, y);
    exit(-1);
  }
 
  if(isdigit(field->field[y][x]))
  {
    field->field[y][x] = 'X';
    field->hits++;
    return(TRUE); 
  }

  field->field[y][x] = 'x';
  return(FALSE);
}

/** process an attack response **/
bool process_attack_response(game_session *g, net_msg *msg)
{
  if(msg->msg_type == MSG_TYPE_GAME_HIT)
  {
    printf("HIT!\n");
    g->field_b.field[msg->point.y][msg->point.x] = 'X';
    g->field_b.hits++;                        
  }
  else if (msg->msg_type == MSG_TYPE_GAME_FAILED)
  {
    printf("FAILED\n");
    g->field_b.field[msg->point.y][msg->point.x] = '~';
  }
  else return(FALSE);

  return(TRUE);
}

/** write to network **/
int net_write(game_session *g, net_msg *msg)
{
  int rs;

  _err((rs = send(g->sock, msg, sizeof(net_msg), 0)) != sizeof(net_msg));
  return(rs);
}

/** read from network **/
int net_read(game_session *g, net_msg *msg)
{
  int rs;

  _err((rs = recv(g->sock, msg, sizeof(net_msg), 0)) < 1);
  if(msg->msg_version != RKUBS_NET_VERSION_N)
  {
    fprintf(stderr,"Received packet of wrong version: %i\n",
      msg->msg_version);
    exit(-1);
  }

  return(rs);
}

/** finish the game, check for cheats and print resume **/
void finish(game_session *g)
{
  net_msg msg;
  hash_t  h;

  msg.msg_version = RKUBS_NET_VERSION_N;
  msg.msg_type = MSG_TYPE_GAME_FINISHED;
  msg.field = g->field_a;

  net_write(g, &msg);

  while(1)
  {
    net_read(g, &msg);
    if(msg.msg_type == MSG_TYPE_GAME_FINISHED)
    {
      int r;
      int c;

      for(r = 0; r < BFIELD_SIZEY; r++)
        for(c = 0; c < BFIELD_SIZEX; c++)
        {
          if(g->field_b.field[r][c] != 'X' && g->field_b.field[r][c] != 'x')
            g->field_b.field[r][c] = msg.field.field[r][c];
        }

        memcpy(&g->field_b.key, &msg.field.key, sizeof(g->field_b.key));
        break;
      }
  }

  printf("*** Resolving...\n");
  print_fields(g, TRUE);

  printf("*** %s WON the game! ***\n\n",
    (g->field_a.hits>g->field_b.hits) ? g->field_b.player_name : "You");

  /* check hash */
  hmac_battlefield(&g->field_b, &h);
  if(memcmp(&h, g->opponent_hash, sizeof(h)))
  {
    fprintf(stderr,"HASH CHECK FAILED!%c\n", 0x07);
    fprintf(stderr,"Your opponent was possibly cheating.\n\n");
    sleep(2);
  }

  printf("Game over.\n\n");
  exit(0);
}

/** get data from /dev/urandom **/
void get_randomdev_data(void *buf, size_t size)
{
  int f;

  _err((f = open("/dev/urandom",O_RDONLY)) == -1);
  _err((read(f, buf, size)) != size);
  close(f);
}

/** hash the battlefield **/
void hmac_battlefield(battlefield *f, hash_t *buf)
{
  unsigned char k_ipad[sizeof(f->key)+1];
  unsigned char k_opad[sizeof(f->key)+1];
  unsigned char data[BFIELD_SIZEX*BFIELD_SIZEY];
  SHA_CTX       c;
  int           i;
  int           x;
  int           pieces = 0;
  unsigned char *p;

  bzero(&data, sizeof(data));
  p = (unsigned char*)&data;
  for(i = 0; i < BFIELD_SIZEY; i++)
  {
    for(x = 0; x < BFIELD_SIZEX; x++)
    {
      *p = (f->field[i][x] == 'X' || isdigit(f->field[i][x])) ? 1 : 0;
      if(*p++) pieces++;
    }
  }

  if(pieces != SHIP_PIECES)
  {
    fprintf(stderr,"\n*** Field with invalid ship count! (%i)\n", pieces);
    sleep(2);
  }

  bzero(k_ipad, sizeof(k_ipad));
  bzero(k_opad, sizeof(k_opad));
  bcopy(f->key, k_ipad, sizeof(f->key));
  bcopy(f->key, k_opad, sizeof(f->key));

  for(i = 0; i < sizeof(f->key); i++)
  {
    k_ipad[i] ^= 0x36;
    k_opad[i] ^= 0x5c;
  }

  /* inner */
  SHA1_Init(&c);
  SHA1_Update(&c, k_ipad, sizeof(f->key));
  SHA1_Update(&c, data, sizeof(data));
  SHA1_Final((unsigned char*)buf, &c);

  /* outer */
  SHA1_Init(&c);
  SHA1_Update(&c, k_opad, sizeof(f->key));
  SHA1_Update(&c, buf, sizeof(hash_t));
  SHA1_Final((unsigned char*)buf, &c);
}

