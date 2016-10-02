import os
import sys
import subprocess
import re
import json
import socket
import time
import ConfigParser
import SimpleHTTPServer
import SocketServer
import BaseHTTPServer
import textwrap

import click

CONFIG_FILEPATH = 'config.ini'
DEFAULT_SUBDIRECTORY = 'dist'
CACHE_CONTROL = 'max-age=300' # 5 min
CLOUDFRONT_MIN_CACHE = 60 * 60 * 24 * 7 # 1 week

# Note:
# Currently we're always setting max-age=300 (5min) cache control on all
# objects.  This (should) ensure that browsers + intermediary caches don't need
# much busting.  Additionally we set min TTL on the cloudfront distributions to
# 1 week, so the CDN edges will hold the content for a long time and not have to
# make requests back to the origin unless we explicitly invalidate them (which
# we do when publishing).  It's not ideal obviously, but seems an ok starting
# point.
# docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Expiration.html


# =============================================================================
# CLI stuff
# =============================================================================

# Wierd click stuff to allow our config to be passed around
pass_config = click.make_pass_decorator(ConfigParser.SafeConfigParser)

@click.group()
@click.version_option('0.1')
@click.pass_context
def cli(ctx):
    """
    Tools to help maintain static sites on AWS.
    """
    # In case this script is called from a different directory, let's change
    # into the directory this file is in so we know where we are.
    os.chdir(os.path.dirname(os.path.realpath(__file__)))

    # Load up the config
    config = ConfigParser.SafeConfigParser()
    config.read(CONFIG_FILEPATH)
    ctx.obj = config


@cli.command()
@click.argument('site')
@pass_config
def publish(config, site):
    """
    Publish the given site to aws.

    This will sync local files with live and invalidate the CDN cache for any
    changed files.  Note that cache invalidations can take a while, so you may
    not see changes on live immediately.
    """
    bucket = config.get(site, 'bucket')
    source = os.path.join(
        os.path.curdir,
        config.get(site, 'directory'),
        config.get(site, 'sub_directory')
    )
    destination = 's3://{bucket}/{site}'.format(bucket=bucket, site=site)

    sync_cmd = ' '.join(
        [
            'aws --profile mkk',
            's3 sync',
            '--acl public-read',
            "--cache-control '{cache}'",
            '--delete', # bad idea?
            '{source}',
            '{destination}'
        ]
    ).format(cache=CACHE_CONTROL, source=source, destination=destination)

    # Do a dry run first, and ask for confirmation
    click.echo("Here's what we're about to do...")
    subprocess.check_call(sync_cmd + ' --dryrun', shell=True)
    click.confirm('Does that seem reasonable?', abort=True)

    # Ok, run the actual sync with s3 (capturing output)
    click.echo('Ok, syncing with s3...')
    s3_sync_output = subprocess.check_output(sync_cmd, shell=True)

    # Work out what files were synced so we know what to invalidate in CDN cache
    changed_files = get_changed_files_from_s3_sync_output(
        s3_sync_output,
        prefix=destination
    )
    if not changed_files:
        click.echo('Nothing to do!')
        return
    click.echo('Done sync')

    # For any files like 'blah/index.html' also invalidate 'blah', 'blah/'
    for object_path in set(changed_files):
        if not object_path.endswith('/index.html'):
            continue
        www_path = object_path.rstrip('/index.html')
        changed_files.add(www_path) if www_path else None
        changed_files.add(www_path + '/')

    distribution = config.get(site, 'cloudfront_distribution_id')
    invalidation = generate_cloudfront_invalidation(changed_files)

    cache_inavlidation_cmd = ' '.join(
        [
            'aws --profile mkk',
            'cloudfront create-invalidation',
            '--distribution-id {distribution}',
            "--invalidation-batch '{invalidation}'"
        ]
    ).format(distribution=distribution, invalidation=invalidation)

    # Invalidate the changed files in cloudfront
    click.echo('Invalidating CDN cache for objects...')
    [click.echo('*  ' + obj) for obj in changed_files]
    cache_invalidation_output = subprocess.check_output(
        cache_inavlidation_cmd,
        shell=True
    )
    cache_invalidation_data = json.loads(
        cache_invalidation_output
    )['Invalidation']
    click.echo(
        'Cache invalidation {invalidation_id} created'
        .format(invalidation_id=cache_invalidation_data['Id'])
    )



@cli.command('purge-cache')
@click.argument('site')
@pass_config
def purge_cache(config, site):
    """
    Invalidate all objects in the CDN (last resort)

    Note that cache invalidations can take a while, so you may not see changes
    on live immediately.
    """
    bucket = config.get(site, 'bucket')
    distribution = config.get(site, 'cloudfront_distribution_id')
    invalidation = generate_cloudfront_invalidation(['/*'])

    cache_inavlidation_cmd = ' '.join(
        [
            'aws --profile mkk',
            'cloudfront create-invalidation',
            '--distribution-id {distribution}',
            "--invalidation-batch '{invalidation}'"
        ]
    ).format(distribution=distribution, invalidation=invalidation)

    click.echo('Purging CDN cache...')
    cache_invalidation_output = subprocess.check_output(
        cache_inavlidation_cmd,
        shell=True
    )
    cache_invalidation_data = json.loads(
        cache_invalidation_output
    )['Invalidation']
    click.echo(
        'Cache invalidation {invalidation_id} created'
        .format(invalidation_id=cache_invalidation_data['Id'])
    )



@cli.command('create-site')
@click.argument('domain-name')
@pass_config
def create_site(config, domain_name):
    """
    Create a new static site for the given domain name.

    We'll create the local folder structure, cloudfront cdn distribution, and
    update the config file.

    Note that it can take a while for cloudfront distributions to get created.
    """
    # Ensure it's a reasonable site (domain) name.  Should have a subdomain.
    site = domain_name.strip()
    if len(site.split('.')) < 3:
        click.echo('\n' + textwrap.fill(textwrap.dedent('''\
            WARNING: Hmm... it's best to create a site name with a subdomain
            e.g. 'www.test.com' as you can't create CNAME DNS records for naked
            domains (e.g. 'test.com').  And you'll probably want to use a CNAME
            record to point to the cloudfront CDN distribution we're gonna
            create for you.
            ''')) + '\n'
        )
        click.confirm(
            "Are you sure you want to carry on with '{site}'".format(site=site),
            abort=True
        )

    # Check to see if that site exists
    if config.has_section(site):
        click.echo('\n' + textwrap.fill(textwrap.dedent('''\
            WARNING: It looks like '{site}' is already set up.  There is a
            section for it in '{config}'.  If we carry on we will overwrite the
            existing config.
            '''.format(site=site, config=CONFIG_FILEPATH))) + '\n'
        )
        click.confirm(
            "Are you sure you want to carry on with '{site}'".format(site=site),
            abort=True
        )


    # Create local folder structure
    # TODO: check existence etc
    click.echo('Creating new directory for site files...')
    directory = site
    sub_directory = DEFAULT_SUBDIRECTORY
    os.mkdir(os.path.join(os.curdir, directory))
    os.mkdir(os.path.join(os.curdir, directory, sub_directory))
    open(os.path.join(os.curdir, directory, '.gitignore'), 'w').close()
    click.echo('Directory {path} created'.format(path=directory))


    # Create a new cloudfront distribution
    distribution_config = generate_cloudfront_distribution_config(
        site,
        config.get('DEFAULT', 'bucket')
    )
    distribution_create_cmd = ' '.join(
        [
            'aws --profile mkk',
            'cloudfront create-distribution',
            "--distribution-config '{distribution_config}'",
        ]
    ).format(distribution_config=distribution_config)

    click.echo('Configuring new cloudfront distribution...')
    distribution_create_output = subprocess.check_output(
        distribution_create_cmd,
        shell=True
    )
    distribution_data = json.loads(distribution_create_output)['Distribution']
    click.echo(
        'Cloudfront distribution {dist_id} created (http://{domain})'.format(
            dist_id=distribution_data['Id'],
            domain=distribution_data['DomainName']
        )
    )
    click.echo(
        'You probably want to create a DNS CNAME record for {site} = {domain}'
        .format(site=site, domain=distribution_data['DomainName'])
    )


    # Save new config
    click.echo('Saving new configuration...')
    if not config.has_section(site):
        config.add_section(site)
    config.set(site, 'directory', directory)
    config.set(site, 'sub_directory', sub_directory)
    config.set(site, 'cloudfront_distribution_id', distribution_data['Id'])
    config.set(site, 'cloudfront_domain_name', distribution_data['DomainName'])
    with open(CONFIG_FILEPATH, 'w') as fd:
        config.write(fd)
    click.echo('Configuration written to {path}'.format(path=CONFIG_FILEPATH))



@cli.command()
@click.argument('site')
@click.option('--port', default=5000)
@click.option('--host', default='127.0.0.1')
@pass_config
def serve(config, site, port, host):
    """
    Start a basic webserver for the given site.
    """
    # Move into the directory to serve
    os.chdir(
        os.path.join(
            os.path.curdir,
            config.get(site, 'directory'),
            config.get(site, 'sub_directory')
        )
    )

    class ThreadingHTTPServer(
        SocketServer.ThreadingMixIn,
        BaseHTTPServer.HTTPServer
    ):
        allow_reuse_address = True

    Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
    httpd = ThreadingHTTPServer((host, port), Handler)
    sa = httpd.socket.getsockname()

    click.echo(
        'Serving {site} at http://{addr}:{port} ...'
        .format(site=site, addr=sa[0], port=sa[1])
    )

    try:
        httpd.serve_forever()
    except:
        click.echo('Stoping Server...')
        httpd.shutdown()
        click.echo('Done')



# =============================================================================
# Helpers
# =============================================================================

def generate_cloudfront_invalidation(changed_files):
    invalidation_data = {
        'Paths': {
            'Quantity': len(changed_files),
            'Items': list(changed_files)
        },
        'CallerReference': new_aws_caller_reference()
    }
    return json.dumps(invalidation_data)


def generate_cloudfront_distribution_config(site, bucket):
    origin_id = '{bucket}/{site}'.format(bucket=bucket, site=site)
    domain = '{bucket}.s3.amazonaws.com'.format(bucket=bucket)
    log_path = 'cdn-logs/{site}/'.format(site=site)
    comment = 'Website {site} ({bucket})'.format(bucket=bucket, site=site)

    conf = {
        'CallerReference': new_aws_caller_reference(),
        'Aliases': {
            'Quantity': 1,
            'Items': [site]
        },
        'DefaultRootObject': 'index.html',
        'Origins': {
            'Quantity': 1,
            'Items': [
                {
                    'Id': origin_id,
                    'DomainName': domain,
                    'OriginPath': '/' + site,
                    'S3OriginConfig': {
                        'OriginAccessIdentity': ''
                    },
                }
            ]
        },
        'DefaultCacheBehavior': {
            'TargetOriginId': origin_id,
            'ForwardedValues': {
                'QueryString': False,
                'Cookies': {
                    'Forward': 'none',
                },
                'Headers': {
                    'Quantity': 0,
                    'Items': []
                }
            },
            'TrustedSigners': {
                'Enabled': False,
                'Quantity': 0,
                'Items': []
            },
            'ViewerProtocolPolicy': 'allow-all',
            'MinTTL': CLOUDFRONT_MIN_CACHE
        },
        'Comment': comment,
        'Logging': {
            'Enabled': True,
            'IncludeCookies': False,
            'Bucket': domain,
            'Prefix': log_path
        },
        'PriceClass': 'PriceClass_All',
        'Enabled': True,
    }
    return json.dumps(conf)


def new_aws_caller_reference():
    return '{hostname}-{timestamp}'.format(
        hostname=socket.gethostname(),
        timestamp=time.time()
    )


def get_changed_files_from_s3_sync_output(output_string, prefix):
    # Helper regex to parse the output from s3 sync command
    s3_key_re = re.compile(
        r"""
          .*          # some initial guff (e.g. '(dryrun) upload:')
          \s+{prefix} # the site we're uploading to (key follows this)
          ([^\s]+)    # the key we care about, terminated by whitespace
        """.format(prefix=prefix),
        re.VERBOSE
    )

    changed_files = set()

    for line in output_string.splitlines():
        key_match = s3_key_re.match(line)
        if not key_match:
            continue
        key = key_match.group(1)
        changed_files.add(key)

    return changed_files




# =============================================================================
# Main
# =============================================================================

if __name__ == '__main__':
    try:
        cli()
    except subprocess.CalledProcessError as exc:
        click.echo(exc)
        sys.exit(exc.returncode)
    except ConfigParser.NoSectionError as exc:
        click.echo(
            "Error: Config missing for '{section}'"
            .format(section=exc.section)
        )
        sys.exit(1)
    except ConfigParser.NoOptionError as exc:
        click.echo(
            "Error: Config option '{option}' missing for '{section}'"
            .format(section=exc.section, option=exc.option)
        )
        sys.exit(1)
