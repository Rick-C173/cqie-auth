'use strict';
'require view';
'require rpc';
'require ui';

var callGetConfig = rpc.declare({ object: 'cqie-auth', method: 'get_config' });
var callSetConfig = rpc.declare({
	object: 'cqie-auth', method: 'set_config', timeout: 15000,
	parameters: [ 'user', 'password', 'service', 'portal', 'probe' ]
});
var callReset = rpc.declare({ object: 'cqie-auth', method: 'do_reset', timeout: 30000 });

return view.extend({
	load: function() {
		return callGetConfig();
	},

	handleSave: function(ev) {
		var user = document.getElementById('cqie-user').value.trim();
		var password = document.getElementById('cqie-pass').value;
		var service = document.getElementById('cqie-svc').value.trim();
		var portal = document.getElementById('cqie-portal').value.trim();
		var probe = document.getElementById('cqie-probe').value.trim();

		if (!user) {
			ui.addNotification(null, E('p', {}, _('user 不能为空')), 'error');
			return;
		}

		var self = this;
		return callSetConfig(user, password, service, portal, probe).then(function(res) {
			if (res.ok) {
				ui.addNotification(null, E('p', {}, _('配置已保存（权限 600）。下次登录生效。')), 'info');
				document.getElementById('cqie-pass').value = '';
				self.renderReset();
			}
			else
				ui.addNotification(null, E('p', {}, res.error || _('保存失败')), 'error');
		}).catch(function(e) {
			ui.addNotification(null, E('p', {}, _('调用异常：%s').format(e.message || e)), 'error');
		});
	},

	handleReset: function(ev) {
		if (!window.confirm(_('确定删除配置文件？删除后将回到未配置状态，需重新填写账号密码。')))
			return;

		var self = this;
		return callReset().then(function(res) {
			if (res.ok) {
				ui.addNotification(null, E('p', {}, _('配置已删除。')), 'info');
				return callGetConfig().then(function(conf) {
					self.reloadForm(conf);
				});
			}
			ui.addNotification(null, E('p', {}, res.error || _('删除失败')), 'error');
		}).catch(function(e) {
			ui.addNotification(null, E('p', {}, _('调用异常：%s').format(e.message || e)), 'error');
		});
	},

	reloadForm: function(conf) {
		document.getElementById('cqie-user').value = conf.user || '';
		document.getElementById('cqie-pass').value = '';
		document.getElementById('cqie-pass').placeholder =
			conf.has_password ? _('已设置（留空保持不变）') : _('未设置');
		document.getElementById('cqie-svc').value = conf.service || '';
		document.getElementById('cqie-portal').value = conf.portal || '';
		document.getElementById('cqie-probe').value = conf.probe || '';
	},

	render: function(conf) {
		var self = this;

		var mk = function(id, value, ph, type) {
			return E('input', {
				'id': id,
				'type': type || 'text',
				'class': 'cbi-input-text',
				'style': 'width:320px',
				'value': value || '',
				'placeholder': ph || ''
			});
		};

		var passPh = conf.has_password ? _('已设置（留空保持不变）') : _('未设置');
		var passIn = mk('cqie-pass', '', passPh, 'password');
		var svcIn = mk('cqie-svc', conf.service, _('留空=登录时自动逐项尝试并写回'));

		var view = E('div', {}, [
			E('h2', {}, _('账号设置')),
			E('div', { 'class': 'cbi-map-descr' },
				_('编辑 /etc/cqie-auth.conf（权限 600）。密码明文保存在路由器上，请确保管理界面访问安全。')),
			E('div', { 'class': 'cbi-section' }, [
				E('table', { 'class': 'table' }, [
					E('tr', {}, [ E('td', { 'width': '33%' }, _('用户名')), E('td', {}, mk('cqie-user', conf.user, _('学号/工号'))) ]),
					E('tr', {}, [ E('td', {}, _('密码')), E('td', {}, passIn) ]),
					E('tr', {}, [
						E('td', {}, _('运营商')),
						E('td', {}, [
							svcIn,
							E('div', { 'class': 'cbi-value-description' },
								_('须与认证页下拉列表名称完全一致；留空则登录时自动逐项尝试'))
						])
					]),
					E('tr', {}, [
						E('td', {}, _('认证服务器')),
						E('td', {}, [
							mk('cqie-portal', conf.portal, _('默认 http://10.253.3.84/eportal')),
							E('div', { 'class': 'cbi-value-description' }, _('可选：学校更换认证服务器时填写'))
						])
					]),
					E('tr', {}, [
						E('td', {}, _('探测地址')),
						E('td', {}, [
							mk('cqie-probe', conf.probe, _('默认 http://123.123.123.123')),
							E('div', { 'class': 'cbi-value-description' }, _('可选：保持 http:// 纯 IP 形式'))
						])
					])
				]),
				E('div', { 'class': 'cbi-page-actions' }, [
					E('button', {
						'class': 'cbi-button cbi-button-apply',
						'click': ui.createHandlerFn(self, 'handleSave')
					}, _('保存')),
					'\xa0',
					E('button', {
						'class': 'cbi-button cbi-button-negative',
						'click': ui.createHandlerFn(self, 'handleReset')
					}, _('删除配置'))
				])
			])
		]);

		return view;
	}
});
