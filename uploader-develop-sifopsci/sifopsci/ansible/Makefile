.PHONY: create_role run_playbook install_role

create_role:
	@sudo docker run --rm \
		-v $(CURDIR)/roles:/etc/ansible/roles \
		pad92/ansible-alpine:2.10.7 \
		ansible-galaxy init \
			$(role) \
			--init-path=/etc/ansible/roles

ansible_version:
	@sudo docker run --rm \
		-v $(CURDIR):/crv-ansible \
		-w /crv-ansible \
		pad92/ansible-alpine:2.10.7 \
		ansible --version
install_role:
	@sudo docker run --rm \
		-v $(CURDIR):/crv-ansible \
		-w /crv-ansible \
		pad92/ansible-alpine:2.10.7 \
		ansible-galaxy install $(role)

run_playbook:
	@sudo docker run --rm \
		-v /home/ec2-user/.ssh/id_rsa:/root/.ssh/id_rsa \
		-v /home/ec2-user/.ssh/id_rsa.pub:/root/.ssh/id_rsa.pub \
                -v /home/ec2-user/S2M_OFFLINE_INSTALLATION.pem:/root/S2M_OFFLINE_INSTALLATION.pem \
		-v $(CURDIR)/roles:/etc/ansible/roles \
		-v $(CURDIR):/crv-ansible \
		-w /crv-ansible \
		pad92/ansible-alpine:2.10 \
		ansible-playbook -i production.yml site.yml 
