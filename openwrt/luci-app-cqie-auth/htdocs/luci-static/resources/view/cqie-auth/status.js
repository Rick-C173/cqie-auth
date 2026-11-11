'use strict';
'require view';
'require poll';
'require rpc';
'require ui';

var callGetStatus = rpc.declare({ object: 'cqie-auth', method: 'get_status' });
var callGetConfig = rpc.declare({ object: 'cqie-auth', method: 'get_config' });
var callGetLogread = rpc.declare({ object: 'cqie-auth', method: 'get_logread' });
var callLogin = rpc.declare({ object: 'cqie-auth', method: 'do_login', timeout: 30000 });
var callLogout = rpc.declare({ object: 'cqie-auth', method: 'do_logout', timeout: 30000 });
var callReauth = rpc.declare({ object: 'cqie-auth', method: 'do_reauth', timeout: 60000 });

var stateText = { 0: _('在线'), 1: _('未在线'), 2: _('不在校园网') };
var stateLabel = { 0: 'label-success', 1: 'label-warning', 2: 'label-important' };

function notify(res) {
	var head = res.ok ? _('操作完成') : _('操作失败（退出码 %s）').format(res.rc);
	var body = (res.output || '').split('\n').filter(function(l) { return l !== ''; }).join('；');
	ui.addNotification(null, E('p', {}, head, E('br'), body || _('（无输出）')), res.ok ? 'info' : 'error');
}

return view.extend({
	load: function() {
		return Promise.all([ callGetStatus(), callGetConfig(), callGetLogread() ]);
	},

	updateStatus: function() {
		return Promise.all([ callGetStatus(), callGetConfig() ]).then(function(data) {
			var st = data[0], conf = data[1];
			var badge = document.getElementById('cqie-badge');
			var detail = document.getElementById('cqie-detail');
			if (badge) {
				badge.textContent = stateText[st.code] || st.code;
				badge.className = 'label ' + (stateLabel[st.code] || '');
			}
			if (detail) {
				detail.textContent = (conf.user || _('未配置')) +
					(conf.has_password ? '' : _('（密码未设置）')) +
					(conf.service ? '　·　%s'.format(conf.service) : _('　·　运营商留空自动'));
			}
		});
	},

	handleLogin: function(ev) {
		return callLogin().then(notify).catch(function(e) {
			ui.addNotification(null, E('p', {}, _('调用异常：%s').format(e.message || e)), 'error');
		});
	},

	handleLogout: function(ev) {
		return callLogout().then(notify).catch(function(e) {
			ui.addNotification(null, E('p', {}, _('调用异常：%s').format(e.message || e)), 'error');
		});
	},

	handleReauth: function(ev) {
		return callReauth().then(notify).catch(function(e) {
			ui.addNotification(null, E('p', {}, _('调用异常：%s').format(e.message || e)), 'error');
		});
	},

	render: function(data) {
		var status = data[0], conf = data[1], log = data[2] || {};
		var badge = E('span', { 'id': 'cqie-badge', 'class': 'label ' + (stateLabel[status.code] || '') },
			stateText[status.code] || status.code);
		var detail = E('span', { 'id': 'cqie-detail' },
			(conf.user || _('未配置')) + (conf.has_password ? '' : _('（密码未设置）')));

		var view = E('div', {}, [
			E('h2', {}, _('校园网认证（cqie-auth）')),
			E('div', { 'class': 'cbi-map-descr' },
				_('锐捷 ePortal 校园网认证状态与操作。在线状态每 5 秒自动刷新。')),
			E('div', { 'class': 'cbi-section' }, [
				E('table', { 'class': 'table' }, [
					E('tr', {}, [ E('td', { 'width': '33%' }, _('当前状态')), E('td', {}, badge) ]),
					E('tr', {}, [ E('td', {}, _('账号')), E('td', {}, detail) ])
				]),
				E('div', { 'class': 'cbi-page-actions' }, [
					E('button', {
						'class': 'cbi-button cbi-button-apply',
						'click': ui.createHandlerFn(this, 'handleLogin')
					}, _('上线')),
					'\xa0',
					E('button', {
						'class': 'cbi-button cbi-button-negative',
						'click': ui.createHandlerFn(this, 'handleLogout')
					}, _('下线')),
					'\xa0',
					E('button', {
						'class': 'cbi-button cbi-button-action',
						'click': ui.createHandlerFn(this, 'handleReauth')
					}, _('重新认证'))
				])
			]),
			E('div', { 'class': 'cbi-section' }, [
				E('div', { 'class': 'cbi-section-descr' },
					_('最近认证日志（logread，末 20 行）')),
				E('pre', { 'style': 'max-height:240px; overflow:auto; font-size:12px; white-space:pre-wrap' },
					log.output || _('（暂无日志）'))
			])
		]);

		poll.add(this.updateStatus.bind(this), 5);
		return view;
	},

	handleSaveConfirm: false
});
