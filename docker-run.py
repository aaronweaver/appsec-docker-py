import docker
from docker.errors import APIError
import json
import argparse
import sys
import requests.packages.urllib3 as urllib3
import os
import uuid

urllib3.disable_warnings()

#Connect to docker host
def connect(option, host):
    print option
    if option == "local":
        cli = docker.Client(base_url='unix://var/run/docker.sock')
    elif option == "remote":
        if os.environ['dockercert'] is None or os.environ['dockerkey'] is None:
            print "Please set your dockercert and dockerkey environment variables."
            sys.exit()

        tls_config = docker.tls.TLSConfig(
            client_cert=(os.environ['dockercert'], os.environ['dockerkey']),
            verify=False
        )
        cli = docker.Client(base_url=host, tls=tls_config)
    elif option == "sshtunnel":
        cli = docker.Client(base_url=host)
    else:
        print "Invalid connect option (connect=--local, --remote, --sshtunnel)"
        sys.exit()

    return cli

#Retreive the docker image and output the download status
def pull_image(cli, docker_image):
    #Pull down the docker from docker hub
    for line in cli.pull(docker_image, stream=True):
        if '"progress":' in line:
            try:
                progress = json.loads(line)
                print "Pulling " + docker_image + ": " + progress['progress']
            except:
                pass

#Stop and remove a container
def delete_container(cli, container_id):
    print "Stopping container..."
    cli.stop(container=container_id)
    print "Removing container..."
    cli.remove_container(container=container_id)

#create and run the container on the docker host
def create_run_container(cli, docker_image, container_name_prefix, container_name, port, host_port, command):

    #Verify and get the latest image
    pull_image(cli, docker_image)

    #Create the docker container
    try:
        container = cli.create_container(image=docker_image, name=container_name_prefix + "_" + container_name,
            #labels= {"label1": "value1", "label2": "value2"},
            command=command,
            ports=[port],
            host_config=cli.create_host_config(port_bindings={
                port: (host_port)
            })
            #host_config=cli.create_host_config(port_bindings={
            #    port: ('127.0.0.1',host_port)
            #})
            )

        #Start the container
        cli.start(container)
        inspect = cli.inspect_container(container=container.get('Id'))
        if host_port is None:
            host_port = port

        print "http://" + inspect['NetworkSettings']['Ports'][str(host_port) + '/tcp'][0]['HostIp'] + ":" + inspect['NetworkSettings']['Ports'][str(host_port) + '/tcp'][0]['HostPort']
        #print inspect
        #cli.stop(container=container.get('Id'))
        #cli.remove_container(container=container.get('Id'))

    except APIError as api_error:
        if "port is already allocated" in str(api_error):
            print "Port is already allocated"
        else:
            raise Exception("Docker API Error : %s" % str(api_error))

def exec_command(cli, docker_image, container_name_prefix, container_name, start_command, command, environment=None):

    if environment is not None:
        environment = [env.strip() for env in environment.split('-e')]

    pull_image(cli, docker_image)
    container = cli.create_container(image=docker_image, name=container_name_prefix + "_" + container_name, command=start_command, environment=environment, tty=True)

    #Start the container
    cli.start(container)
    #cli.start(container=container.get('Id'),links=(('EXISTING_CONTAINER', 'LINK_NAME'))

    #Prepare for command exec
    exec_c = cli.exec_create(container,cmd=command,tty=True)

    #Retrieve standard output
    for line in cli.exec_start(exec_c, stream=True):
        print line

    delete_container(cli, container.get('Id'))

class Main:
    if __name__ == "__main__":

        parser = argparse.ArgumentParser(description='Deploy docker security containers.')
        parser.add_argument('--connect', default='local', help="Docker host, local or sshtunnel ", required=True)
        parser.add_argument('--host', help="Docker host, local or remote (tcp://hostname:2376). Set environment variable dockercert and dockerkey.", required=False)
        parser.add_argument('--tool', help='Name of the security tool', required=True)
        parser.add_argument('--build', help='Name of the build or prefix', required=True)
        parser.add_argument('--image', help='Docker image')
        parser.add_argument('--startcmd', help='Command to start the docker container')
        parser.add_argument('--cmd', help='Command to run on the docker container')
        parser.add_argument('--env', help='Environment variables to pass to the container')

        #Parse out arguments
        args = vars(parser.parse_args())
        tool = args["tool"]
        build_name = args["build"]
        build_name = build_name + "-" + str(uuid.uuid4())
        start_command = args["startcmd"]
        command = args["cmd"]
        image = args["image"]
        host = args["host"]
        option = args["connect"]
        environment = args["env"]

        cli = connect(option, host)

        if tool == "zap":
            create_run_container(cli, 'owasp/zap2docker-stable', build_name, "zap", 8080, 80, 'zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true')
        elif tool == "zap-dojo":
            exec_command(cli, 'aweaver/zap-auth', build_name, "zap", "/bin/bash", '/home/zap/app_sec_scan/run.sh', environment=environment)
        elif tool == "nikto":
            #exec_command(cli, docker_image, container_name_prefix, container_name, start_command, command):
            exec_command(cli, 'kali-pipeline', build_name, tool, "/bin/bash", "/bin/bash /usr/local/bin/run.sh 'nikto -h " + command + " -T 58' nikto.txt aaron")
        elif tool == "wpscan":
            #exec_command(cli, docker_image, container_name_prefix, container_name, start_command, command):
            exec_command(cli, 'kali-pipeline', build_name, tool, "/bin/bash", "/bin/bash /usr/local/bin/run.sh 'wpscan -u " + command + " --update' wpscan.txt aaron")
        elif tool == "dirb":
            #exec_command(cli, docker_image, container_name_prefix, container_name, start_command, command):
            exec_command(cli, 'kali-pipeline', build_name, tool, "/bin/bash", "/bin/bash /usr/local/bin/run.sh 'dirb " + command + " /usr/share/dirb/wordlists/common.txt' dirb.txt aaron")
        elif tool == "arachni":
            create_run_container(cli, 'ahannigan/docker-arachni', build_name, "arachni", 9292, None, 'bin/arachni_web -o 0.0.0.0')
        elif tool == "bodgeit":
            create_run_container(cli, 'psiinon/bodgeit', build_name, "arachni", 8080, None, None)
        elif tool == "alpine":
            if command is None:
                print "Please provide a command to run on the container. (--cmd)"
                sys.exit()
            exec_command(cli, 'alpine', build_name, 'alpine', '/bin/ash', command)
        elif tool == "adhoc":
            if image is None:
                print "Please provide an image to pull. (--image)"
                sys.exit()
            if command is None:
                print "Please provide a command to start the container. (--cmd)"
                sys.exit()
            if command is None:
                print "Please provide a command to run on the container. (--cmd)"
                sys.exit()
            exec_command(cli, image, build_name, image, startcmd, command)
