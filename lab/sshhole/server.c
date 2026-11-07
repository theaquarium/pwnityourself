/*
 * Intentionally-vulnerable SSH server for the PIY "sshhole" lab.
 *
 * Built on libssh, it offers password authentication and, once a client is
 * authenticated, lets that client run a command over an "exec" channel.  Like
 * most libssh servers it trusts the library to enforce authentication and
 * only wires up its own channel/exec handlers.
 *
 * When linked against a libssh in the 0.6.0-0.7.5 / 0.8.0-0.8.3 range
 * (CVE-2018-10933), a client can send SSH2_MSG_USERAUTH_SUCCESS -- a message
 * only a *server* should ever send -- and the library flips its own state to
 * "authenticated", letting channels through with no credentials.
 *
 * Modelled on libssh's own examples/ssh_server.c.
 */
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define USER "admin"
#define PASS "hunter2-correct-horse"

/* Forward declaration so channel_open can reference the exec callback. */
static int exec_request(ssh_session, ssh_channel, const char *, void *);

struct session_data {
    ssh_channel channel;
    int auth_attempts;
    int authenticated;
    struct ssh_channel_callbacks_struct channel_cb;
};

static int auth_password(ssh_session session, const char *user,
                         const char *pass, void *userdata) {
    struct session_data *sdata = (struct session_data *) userdata;
    (void) session;
    if (strcmp(user, USER) == 0 && strcmp(pass, PASS) == 0) {
        sdata->authenticated = 1;
        return SSH_AUTH_SUCCESS;
    }
    sdata->auth_attempts++;
    return SSH_AUTH_DENIED;
}

/* Run the client's command and stream its output back over the channel. */
static int exec_request(ssh_session session, ssh_channel channel,
                       const char *command, void *userdata) {
    (void) session;
    (void) userdata;
    FILE *fp;
    char buf[4096];
    size_t n;

    fprintf(stderr, "[server] exec: %s\n", command);
    fflush(stderr);

    fp = popen(command, "r");
    if (fp == NULL) return SSH_ERROR;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
        ssh_channel_write(channel, buf, (uint32_t) n);
    pclose(fp);
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    return SSH_OK;
}

/*
 * Called by libssh when the (supposedly authenticated) client requests a
 * session channel.  We attach the exec handler right here, inside the
 * callback, so it is already in place before libssh processes the next
 * message in the same event-loop tick.
 */
static ssh_channel channel_open(ssh_session session, void *userdata) {
    struct session_data *sdata = (struct session_data *) userdata;
    sdata->channel = ssh_channel_new(session);
    /* Attach exec handler immediately -- no gap for a race. */
    ssh_set_channel_callbacks(sdata->channel, &sdata->channel_cb);
    fprintf(stderr, "[server] channel opened (authenticated=%d)\n",
            sdata->authenticated);
    fflush(stderr);
    return sdata->channel;
}

static void handle_session(ssh_event event, ssh_session session) {
    struct session_data sdata;
    struct ssh_server_callbacks_struct server_cb;

    memset(&sdata, 0, sizeof(sdata));
    memset(&server_cb, 0, sizeof(server_cb));

    /* Pre-initialize channel callbacks so channel_open can use them. */
    memset(&sdata.channel_cb, 0, sizeof(sdata.channel_cb));
    sdata.channel_cb.userdata = &sdata;
    sdata.channel_cb.channel_exec_request_function = exec_request;
    ssh_callbacks_init(&sdata.channel_cb);

    server_cb.userdata = &sdata;
    server_cb.auth_password_function = auth_password;
    server_cb.channel_open_request_session_function = channel_open;
    ssh_callbacks_init(&server_cb);

    ssh_set_server_callbacks(session, &server_cb);

    if (ssh_handle_key_exchange(session) != SSH_OK) {
        fprintf(stderr, "[server] key exchange failed: %s\n",
                ssh_get_error(session));
        return;
    }
    fprintf(stderr, "[server] key exchange done; awaiting auth\n");
    fflush(stderr);

    ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);
    ssh_event_add_session(event, session);

    /* Pump until a channel appears (libssh gates channel_open on its own
       internal auth state) or we time out. */
    int n = 0;
    while (sdata.channel == NULL) {
        if (ssh_event_dopoll(event, 100) == SSH_ERROR) {
            fprintf(stderr, "[server] poll error: %s\n",
                    ssh_get_error(session));
            return;
        }
        if (++n > 600) {
            fprintf(stderr, "[server] timeout waiting for channel\n");
            return;
        }
    }

    /* Keep pumping until the command has run and the channel is closed. */
    for (n = 0; n < 300; n++) {
        if (ssh_event_dopoll(event, 100) == SSH_ERROR) break;
        if (!ssh_channel_is_open(sdata.channel)) break;
    }
}

int main(int argc, char **argv) {
    const char *port = (argc > 1) ? argv[1] : "2022";
    ssh_bind sshbind;

    ssh_init();
    sshbind = ssh_bind_new();
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, "/lab/host_rsa");

    if (ssh_bind_listen(sshbind) < 0) {
        fprintf(stderr, "listen failed: %s\n", ssh_get_error(sshbind));
        return 1;
    }
    fprintf(stderr, "[server] vulnerable libssh server on port %s\n", port);
    fflush(stderr);

    while (1) {
        ssh_session session = ssh_new();
        if (ssh_bind_accept(sshbind, session) == SSH_ERROR) {
            fprintf(stderr, "accept failed: %s\n", ssh_get_error(sshbind));
            ssh_free(session);
            continue;
        }
        ssh_event event = ssh_event_new();
        handle_session(event, session);
        ssh_event_free(event);
        ssh_disconnect(session);
        ssh_free(session);
    }
    ssh_bind_free(sshbind);
    ssh_finalize();
    return 0;
}
