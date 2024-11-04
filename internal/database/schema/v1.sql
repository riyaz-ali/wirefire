-- This sql migration sets up the base relations for the wirefire service.

-- enable support for foreign_keys
PRAGMA foreign_keys = ON;

-- Table users store minimal user profile information fetched from oidc provider
CREATE TABLE users
(
    id         INTEGER PRIMARY KEY,                     -- auto-generated, sequential identifier for the user
    sub        GENERATED ALWAYS AS (claims ->> 'sub'),  -- unique subject extracted from oidc token
    name       GENERATED ALWAYS AS (claims ->> 'name'), -- user's name extracted from the oidc token
    claims     JSON NOT NULL,                           -- OIDC standard claims extracted from the token

    created_at TIMESTAMP DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),

    CONSTRAINT uq_subject UNIQUE (sub)                  -- subject must be unique
);

-- Table tailnets store configuration for all tailnets managed by Wirefire
CREATE TABLE tailnets
(
    id         INTEGER PRIMARY KEY, -- auto-generated, sequential identifier for the tailnet
    name       TEXT UNIQUE,         -- user-provided, unique name for the tailnet

    -- tailnet's ACL Policy (https://tailscale.com/kb/1018/acls)
    -- default value is an allow-all policy from https://tailscale.com/kb/1192/acl-samples#allow-all-default-acl
    acl        JSON      DEFAULT '{ "acls": [{ "action": "accept", "src": ["*"], "dst": ["*:*"] }] }',

    created_at TIMESTAMP DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TIMESTAMP DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Table tailnet_members store membership information for a given (tailnet, user) pair.
-- Membership assignment depends on wirefire's iam assignment policy managed in code.
CREATE TABLE tailnet_members
(
    tailnet_id INTEGER NOT NULL,                    -- the referenced tailnet
    user_id    INTEGER NOT NULL,                    -- the referenced user
    role       TEXT    NOT NULL DEFAULT ('member'), -- the assigned role in the tailnet

    created_at TIMESTAMP        DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (tailnet_id, user_id),

    CONSTRAINT fk_member_tailnet FOREIGN KEY (tailnet_id) REFERENCES tailnets (id) ON DELETE CASCADE,
    CONSTRAINT fk_member_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Table machine_registration_requests stores data passed during the initial /machine/register request by the client.
-- The data here is later matched in subsequent requests and after authentication is complete.
-- When the request is first created, the machine is not registered to any user / associated with any tailnet.
CREATE TABLE machine_registration_requests
(
    id            TEXT PRIMARY KEY,        -- auto-generated text id used to identify requests in callback; exposed in callback endpoint
    noise_key     TEXT NOT NULL,           -- machine's public key used when establishing secure Noise channel over /ts2021
    data          JSON,                    -- serialized tailcfg.RegisterRequest object passed to /machine/register
    authenticated BOOL      DEFAULT false, -- is the request authenticated? starts in un-authenticated state and moves to authenticated after oidc flow completes successfully
    user_id       INTEGER,                 -- id of the user who authenticated the request
    error         TEXT,

    created_at    TIMESTAMP DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),

    CONSTRAINT fk_request_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Table machines store information about the node such as all the relevant keys, endpoints, user and tailnet information.
CREATE TABLE machines
(
    id         INTEGER PRIMARY KEY,     -- auto-generated unique machine identifier
    name       TEXT NOT NULL,           -- machine's hostname
    name_idx   INTEGER   DEFAULT 0,     -- arbiter used as suffix to guarantee unique hostname within a given tailnet
    noise_key  TEXT NOT NULL,           -- machine's public key used when establishing secure Noise channel over /ts2021
    node_key   TEXT NOT NULL,           -- key used for wireguard tunnel and for communication over DERP
    disco_key  TEXT NOT NULL,           -- key used for peer-to-peer path discovery
    ephemeral  BOOLEAN   DEFAULT false, -- is the device ephemeral?
    host_info  JSON,                    -- serialized tailcfg.HostInfo object from either the first registration request or subsequent map requests
    endpoints  JSON,                    -- machine's magicsock UDP ip:port endpoints (can be public and / or private addresses)
    ipv4       integer,                 -- assigned IPv4 address for this node

    created_at TIMESTAMP DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at datetime,
    last_seen  datetime,

    tailnet_id integer,                 -- tailnet that this node belongs to
    user_id    integer,                 -- user this node belongs to

    CONSTRAINT fk_machine_tailnet FOREIGN KEY (tailnet_id) REFERENCES tailnets (id),
    CONSTRAINT fk_machine_user FOREIGN KEY (user_id) REFERENCES users (id),

    -- machine's life is tied to the owner's membership in a tailnet
    -- this foreign key relation enforces it
    CONSTRAINT fk_membership FOREIGN KEY (tailnet_id, user_id) REFERENCES tailnet_members (tailnet_id, user_id) ON DELETE CASCADE
);

-- Index idx_tailnet_id_name is used when assigning name_idx to new machines.
-- The value name_idx+1 is used if a machine with the same name already exists in the tailnet.
CREATE UNIQUE INDEX idx_tailnet_id_name ON machines (tailnet_id, name, name_idx desc);

-- Index idx_noise_node_key is used inside /machine/map handler to locate a given machine
-- using its Noise+Node keys, as when we receive the request those are the only two inputs available to us (to locate the machine)
CREATE UNIQUE INDEX idx_noise_node_key ON machines (noise_key, node_key);