.PHONY: install test plan apply clean

install:
	@echo "Installing dependencies..."
	@which terraform > /dev/null || (echo "Please install Terraform" && exit 1)
	@which conftest > /dev/null || (echo "Please install Conftest" && exit 1)

test:
	@echo "Running compliance tests..."
	conftest test --policy policies/ tests/

plan:
	@echo "Planning Terraform deployment..."
	cd terraform && terraform init && terraform plan

apply:
	@echo "Applying Terraform configuration..."
	cd terraform && terraform apply

clean:
	@echo "Cleaning up..."
	cd terraform && terraform destroy -auto-approve