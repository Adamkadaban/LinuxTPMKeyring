// Gen2 Trusted-Launch Debian 13 VM with a real vTPM 2.0, for tess real-vTPM acceptance.
//
// COST WARNING: deploying this template starts billing a VM. Deallocate when idle
// (deploy/azure/deallocate.sh) and delete at wind-down (deploy/azure/teardown.sh).
//
// Every resource is tagged project=LinuxTPMKeyring so teardown can find and remove it.

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('VM name; also the basis for NIC / IP / disk names.')
param vmName string = 'tess-vtpm'

@description('VM size. B4ms (4 vCPU / 16 GB burstable) is the default per the project budget.')
param vmSize string = 'Standard_B4ms'

@description('Admin username for SSH (key-only auth; no password is ever set).')
param adminUsername string = 'tess'

@description('SSH public key text injected for key-only auth.')
@secure()
param sshPublicKey string

@description('Resource tag applied to every resource so teardown can target the project.')
param projectTag string = 'LinuxTPMKeyring'

@description('Source address/CIDR allowed to reach SSH (port 22). Defaults to "*" (any); provision.sh narrows this to the caller IP when it can.')
param allowedSshSource string = '*'

// Debian 13 (Trixie) Gen2 marketplace image. Gen2 is required for Trusted Launch / vTPM.
// Override via the imageReference params if Debian renames the SKU.
@description('Marketplace image publisher.')
param imagePublisher string = 'Debian'

@description('Marketplace image offer.')
param imageOffer string = 'debian-13'

@description('Marketplace image SKU (Gen2).')
param imageSku string = '13-gen2'

@description('Marketplace image version.')
param imageVersion string = 'latest'

var tags = {
  project: projectTag
}

var vnetName = '${vmName}-vnet'
var subnetName = 'default'
var nsgName = '${vmName}-nsg'
var nicName = '${vmName}-nic'
var pipName = '${vmName}-pip'

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: nsgName
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'AllowSSHInbound'
        properties: {
          priority: 1000
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          sourceAddressPrefix: allowedSshSource
          destinationPortRange: '22'
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: vnetName
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
    subnets: [
      {
        name: subnetName
        properties: {
          addressPrefix: '10.0.0.0/24'
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
    ]
  }
}

resource pip 'Microsoft.Network/publicIPAddresses@2023-11-01' = {
  name: pipName
  location: location
  tags: tags
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource nic 'Microsoft.Network/networkInterfaces@2023-11-01' = {
  name: nicName
  location: location
  tags: tags
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: '${vnet.id}/subnets/${subnetName}'
          }
          publicIPAddress: {
            id: pip.id
          }
        }
      }
    ]
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2024-03-01' = {
  name: vmName
  location: location
  tags: tags
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    securityProfile: {
      securityType: 'TrustedLaunch'
      uefiSettings: {
        secureBootEnabled: true
        vTpmEnabled: true
      }
    }
    storageProfile: {
      imageReference: {
        publisher: imagePublisher
        offer: imageOffer
        sku: imageSku
        version: imageVersion
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'Premium_LRS'
        }
      }
    }
    osProfile: {
      computerName: vmName
      adminUsername: adminUsername
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUsername}/.ssh/authorized_keys'
              keyData: sshPublicKey
            }
          ]
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
        }
      ]
    }
  }
}

@description('Public IP of the provisioned VM.')
output publicIp string = pip.properties.ipAddress

@description('Admin username for SSH.')
output adminUsername string = adminUsername
