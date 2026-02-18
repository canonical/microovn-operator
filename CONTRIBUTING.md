# Contributing

## Development Setup

This project uses [Poetry](https://python-poetry.org/) for dependency management.
Install Poetry and set up the development environment:

```shell
pip install poetry==2.2.1
make .venv
```

You'll also need `tox` for running tests:

```shell
sudo apt-get install -y tox
```

## Testing

### Linting and Code Checks

Linting and other code checks are done as part of the `check-code` target:

```shell
make check-code
```

### Unit Tests

Unit tests can be run with the `check-unit` target:

```shell
make check-unit
```

### Integration Tests

Integration tests are implemented using the
[Jubilant](https://github.com/canonical/jubilant) framework.

#### Prerequisites

You can set the environment up using [concierge](https://github.com/canonical/concierge) utility
to get started quickly:

```shell
cat <<EOF > /tmp/concierge.yaml
juju:
  channel: 3.6/stable

providers:
  microk8s:
    enable: true
    bootstrap: true
    addons:
      - dns
      - hostpath-storage
      - metallb

  lxd:
    enable: true
    bootstrap: true
EOF

sudo concierge prepare -c /tmp/concierge.yaml
```

You can customize the test environment using these optional environment variables:

- `LXD_CONTROLLER`: Name of the LXD Juju controller (default: `concierge-lxd`)
- `K8S_CONTROLLER`: Name of the MicroK8s Juju controller (default: `concierge-microk8s`)
- `MICROOVN_CHARM_PATH`: Path to a pre-built microovn charm (default: auto-detected from cwd)
- `INTERFACE_CONSUMER_CHARM_PATH`: Path to a pre-built interface-consumer charm (default: auto-detected from `tests/interface-consumer/`)

If you're not using `concierge` to set up your test environment, you can use the
`LXD_CONTROLLER` and `K8S_CONTROLLER` variables to point to your existing Juju
controllers.

#### Running Integration Tests

Execute integration tests using the `check-integration` target:

```shell
make check-integration
```

Optionally tests may be run in parallel, for environments with sufficient
resources:

```shell
make check-integration PARALLEL=4
```

In the event of failure, you may also instruct the test suite to keep
temporarily created models for further investigation:

```shell
make check-integration TESTSUITEFLAGS=--keep-models
```

### Running All Tests

The `check-system` target runs both unit and integration tests:

```shell
make check-system PARALLEL=4
```

The `test` target runs code checks, unit tests, and integration tests:

```shell
make test PARALLEL=4 TESTSUITEFLAGS=--keep-models
```

## Build the charms

Build the charms in this git repository using:

```shell
make build-all
```

## Clean the build environment

Remove files created during build with:

```shell
make clean
```
