import { useEffect, useState } from 'react'
import {
  Card,
  Form,
  Input,
  InputNumber,
  Select,
  Button,
  Tag,
  Space,
  Typography,
  Descriptions,
} from 'antd'
import {
  PlayCircleOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  LoadingOutlined,
} from '@ant-design/icons'
import { apiFetch } from '@/lib/utils'
import { getExecutorOptions, normalizeExecutorForPlatform } from '@/lib/registerOptions'

const { Text } = Typography

export default function Register() {
  const [form] = Form.useForm()
  const [task, setTask] = useState<any>(null)
  const [polling, setPolling] = useState(false)

  useEffect(() => {
    apiFetch('/config').then((cfg) => {
      const currentPlatform = form.getFieldValue('platform') || 'trae'
      form.setFieldsValue({
        executor_type: normalizeExecutorForPlatform(currentPlatform, cfg.default_executor),
        captcha_solver: cfg.default_captcha_solver || 'yescaptcha',
        mail_provider: cfg.mail_provider || 'moemail',
        yescaptcha_key: cfg.yescaptcha_key || '',
        moemail_api_url: cfg.moemail_api_url || '',
        laoudo_auth: cfg.laoudo_auth || '',
        laoudo_email: cfg.laoudo_email || '',
        laoudo_account_id: cfg.laoudo_account_id || '',
        duckmail_api_url: cfg.duckmail_api_url || '',
        duckmail_provider_url: cfg.duckmail_provider_url || '',
        duckmail_bearer: cfg.duckmail_bearer || '',
        freemail_api_url: cfg.freemail_api_url || '',
        freemail_admin_token: cfg.freemail_admin_token || '',
        freemail_username: cfg.freemail_username || '',
        freemail_password: cfg.freemail_password || '',
        cfworker_api_url: cfg.cfworker_api_url || '',
        cfworker_admin_token: cfg.cfworker_admin_token || '',
        cfworker_domain: cfg.cfworker_domain || '',
        cfworker_fingerprint: cfg.cfworker_fingerprint || '',
        luckmail_base_url: cfg.luckmail_base_url || 'https://mails.luckyous.com/',
        luckmail_api_key: cfg.luckmail_api_key || '',
        luckmail_email_type: cfg.luckmail_email_type || '',
        luckmail_domain: cfg.luckmail_domain || '',
        outlook_official_pool_secret: cfg.outlook_official_pool_secret || '',
        outlook_official_login_slug: cfg.outlook_official_login_slug || '',
        outlook_official_base_email: cfg.outlook_official_base_email || '',
        outlook_official_alias_mode: cfg.outlook_official_alias_mode || 'official',
        outlook_official_alias_prefix: cfg.outlook_official_alias_prefix || 'aar',
        outlook_official_target_email: cfg.outlook_official_target_email || '',
        outlook_official_poll_interval: cfg.outlook_official_poll_interval || 5,
        outlook_official_timeout: cfg.outlook_official_timeout || 60,
        outlook_email_base_url: cfg.outlook_email_base_url || '',
        outlook_email_auth_mode: cfg.outlook_email_auth_mode || 'auto',
        outlook_email_api_key: cfg.outlook_email_api_key || '',
        outlook_email_login_password: cfg.outlook_email_login_password || '',
        outlook_email_group_id: cfg.outlook_email_group_id || '',
        outlook_email_address_mode: cfg.outlook_email_address_mode || 'aliases-first',
        outlook_email_address_pool: cfg.outlook_email_address_pool || '',
        outlook_email_folder: cfg.outlook_email_folder || 'all',
        outlook_email_fetch_top: cfg.outlook_email_fetch_top || 10,
        outlook_email_disable_used_accounts: cfg.outlook_email_disable_used_accounts || 'true',
        outlook_email_disable_used_status: cfg.outlook_email_disable_used_status || 'inactive',
        outlook_email_used_addresses_path: cfg.outlook_email_used_addresses_path || '',
        outlook_email_poll_interval: cfg.outlook_email_poll_interval || 5,
        outlook_email_timeout: cfg.outlook_email_timeout || 60,
        outlook_email_proxy: cfg.outlook_email_proxy || '',
      })
    })
  }, [form])

  const submit = async () => {
    const values = await form.validateFields()
    const res = await apiFetch('/tasks/register', {
      method: 'POST',
      body: JSON.stringify({
        platform: values.platform,
        email: values.email || null,
        password: values.password || null,
        count: values.count,
        register_delay_seconds: values.register_delay_seconds || 0,
        proxy: values.proxy || null,
        executor_type: values.executor_type,
        captcha_solver: values.captcha_solver,
        extra: {
          mail_provider: values.mail_provider,
          laoudo_auth: values.laoudo_auth,
          laoudo_email: values.laoudo_email,
          laoudo_account_id: values.laoudo_account_id,
          moemail_api_url: values.moemail_api_url,
          duckmail_api_url: values.duckmail_api_url,
          duckmail_provider_url: values.duckmail_provider_url,
          duckmail_bearer: values.duckmail_bearer,
          freemail_api_url: values.freemail_api_url,
          freemail_admin_token: values.freemail_admin_token,
          freemail_username: values.freemail_username,
          freemail_password: values.freemail_password,
          cfworker_api_url: values.cfworker_api_url,
          cfworker_admin_token: values.cfworker_admin_token,
          cfworker_domain: values.cfworker_domain,
          cfworker_fingerprint: values.cfworker_fingerprint,
          luckmail_base_url: values.luckmail_base_url,
          luckmail_api_key: values.luckmail_api_key,
          luckmail_email_type: values.luckmail_email_type,
          luckmail_domain: values.luckmail_domain,
          outlook_official_pool_secret: values.outlook_official_pool_secret,
          outlook_official_login_slug: values.outlook_official_login_slug,
          outlook_official_base_email: values.outlook_official_base_email,
          outlook_official_alias_mode: values.outlook_official_alias_mode,
          outlook_official_alias_prefix: values.outlook_official_alias_prefix,
          outlook_official_target_email: values.outlook_official_target_email,
          outlook_official_poll_interval: values.outlook_official_poll_interval,
          outlook_official_timeout: values.outlook_official_timeout,
          outlook_email_base_url: values.outlook_email_base_url,
          outlook_email_auth_mode: values.outlook_email_auth_mode,
          outlook_email_api_key: values.outlook_email_api_key,
          outlook_email_login_password: values.outlook_email_login_password,
          outlook_email_group_id: values.outlook_email_group_id,
          outlook_email_address_mode: values.outlook_email_address_mode,
          outlook_email_address_pool: values.outlook_email_address_pool,
          outlook_email_folder: values.outlook_email_folder,
          outlook_email_fetch_top: values.outlook_email_fetch_top,
          outlook_email_disable_used_accounts: values.outlook_email_disable_used_accounts,
          outlook_email_disable_used_status: values.outlook_email_disable_used_status,
          outlook_email_used_addresses_path: values.outlook_email_used_addresses_path,
          outlook_email_poll_interval: values.outlook_email_poll_interval,
          outlook_email_timeout: values.outlook_email_timeout,
          outlook_email_proxy: values.outlook_email_proxy,
          yescaptcha_key: values.yescaptcha_key,
          solver_url: values.solver_url,
        },
      }),
    })
    setTask(res)
    setPolling(true)
    pollTask(res.task_id)
  }

  const pollTask = async (id: string) => {
    const interval = setInterval(async () => {
      const t = await apiFetch(`/tasks/${id}`)
      setTask(t)
      if (t.status === 'done' || t.status === 'failed') {
        clearInterval(interval)
        setPolling(false)
        if (t.cashier_urls && t.cashier_urls.length > 0) {
          t.cashier_urls.forEach((url: string) => window.open(url, '_blank'))
        }
      }
    }, 2000)
  }

  const mailProvider = Form.useWatch('mail_provider', form)
  const captchaSolver = Form.useWatch('captcha_solver', form)
  const platform = Form.useWatch('platform', form)
  const executorOptions = getExecutorOptions(platform)

  useEffect(() => {
    const currentExecutor = form.getFieldValue('executor_type')
    const normalizedExecutor = normalizeExecutorForPlatform(platform, currentExecutor)
    if (currentExecutor !== normalizedExecutor) {
      form.setFieldValue('executor_type', normalizedExecutor)
    }
  }, [form, platform])

  return (
    <div style={{ maxWidth: 800 }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 24, fontWeight: 'bold', margin: 0 }}>注册任务</h1>
        <p style={{ color: '#7a8ba3', marginTop: 4 }}>创建账号自动注册任务</p>
      </div>

      <Form form={form} layout="vertical" onFinish={submit} initialValues={{
        platform: 'trae',
        executor_type: 'protocol',
        captcha_solver: 'yescaptcha',
        mail_provider: 'moemail',
        count: 1,
        register_delay_seconds: 0,
        solver_url: 'http://localhost:8889',
      }}>
        <Card title="基本配置" style={{ marginBottom: 16 }}>
          <Form.Item name="platform" label="平台" rules={[{ required: true }]}>
            <Select
              options={[
                { value: 'chatgpt', label: 'ChatGPT' },
                { value: 'trae', label: 'Trae.ai' },
                { value: 'cursor', label: 'Cursor' },
                { value: 'kiro', label: 'Kiro' },
                { value: 'grok', label: 'Grok' },
                { value: 'tavily', label: 'Tavily' },
                { value: 'openblocklabs', label: 'OpenBlockLabs' },
              ]}
            />
          </Form.Item>
          <Form.Item name="executor_type" label="执行器" rules={[{ required: true }]}>
            <Select options={executorOptions} />
          </Form.Item>
          <Form.Item name="captcha_solver" label="验证码" rules={[{ required: true }]}>
            <Select
              options={[
                { value: 'yescaptcha', label: 'YesCaptcha' },
                { value: 'local_solver', label: '本地 Solver (Camoufox)' },
                { value: 'manual', label: '手动' },
              ]}
            />
          </Form.Item>
          <Space style={{ width: '100%' }}>
            <Form.Item name="count" label="批量数量" style={{ flex: 1 }}>
              <Input type="number" min={1} />
            </Form.Item>
            <Form.Item name="register_delay_seconds" label="每个注册延迟(秒)" style={{ flex: 1 }}>
              <InputNumber min={0} precision={1} step={0.5} style={{ width: '100%' }} placeholder="0" />
            </Form.Item>
          </Space>
          <Space style={{ width: '100%' }}>
            <Form.Item name="proxy" label="代理 (可选)" style={{ flex: 1 }}>
              <Input placeholder="http://user:pass@host:port" />
            </Form.Item>
          </Space>
        </Card>

        <Card title="邮箱配置" style={{ marginBottom: 16 }}>
          <Form.Item name="mail_provider" label="邮箱服务" rules={[{ required: true }]}>
            <Select
              options={[
                { value: 'moemail', label: 'MoeMail (sall.cc)' },
                { value: 'tempmail_lol', label: 'TempMail.lol' },
                { value: 'duckmail', label: 'DuckMail' },
                { value: 'freemail', label: 'Freemail' },
                { value: 'laoudo', label: 'Laoudo' },
                { value: 'cfworker', label: 'CF Worker' },
                { value: 'luckmail', label: 'LuckMail' },
                { value: 'outlook_official_web', label: 'Official Outlook Web' },
                { value: 'outlookapi', label: 'Outlook API' },
              ]}
            />
          </Form.Item>
          {mailProvider === 'laoudo' && (
            <>
              <Form.Item name="laoudo_email" label="邮箱地址">
                <Input placeholder="xxx@laoudo.com" />
              </Form.Item>
              <Form.Item name="laoudo_account_id" label="Account ID">
                <Input placeholder="563" />
              </Form.Item>
              <Form.Item name="laoudo_auth" label="JWT Token">
                <Input placeholder="eyJ..." />
              </Form.Item>
            </>
          )}
          {mailProvider === 'cfworker' && (
            <>
              <Form.Item name="cfworker_api_url" label="API URL">
                <Input placeholder="https://apimail.example.com" />
              </Form.Item>
              <Form.Item name="cfworker_admin_token" label="Admin Token">
                <Input placeholder="abc123,,,abc" />
              </Form.Item>
              <Form.Item name="cfworker_domain" label="域名">
                <Input placeholder="example.com" />
              </Form.Item>
              <Form.Item name="cfworker_fingerprint" label="Fingerprint (可选)">
                <Input placeholder="cfb82279f..." />
              </Form.Item>
            </>
          )}
          {mailProvider === 'luckmail' && (
            <>
              <Form.Item name="luckmail_base_url" label="平台地址">
                <Input placeholder="https://mails.luckyous.com" />
              </Form.Item>
              <Form.Item name="luckmail_api_key" label="API Key">
                <Input.Password placeholder="ak_..." />
              </Form.Item>
              <Form.Item name="luckmail_email_type" label="邮箱类型（可选）">
                <Input placeholder="ms_graph / ms_imap" />
              </Form.Item>
              <Form.Item name="luckmail_domain" label="邮箱域名（可选）">
                <Input placeholder="outlook.com" />
              </Form.Item>
            </>
          )}
          {mailProvider === 'outlook_official_web' && (
            <>
              <Form.Item name="outlook_official_pool_secret" label="Pool Secret 路径">
                <Input placeholder="/home/.../pool.json" />
              </Form.Item>
              <Form.Item name="outlook_official_login_slug" label="登录 slug（可选）">
                <Input.Password placeholder="base@outlook.com----password" />
              </Form.Item>
              <Form.Item name="outlook_official_base_email" label="基础 Outlook 邮箱">
                <Input placeholder="base@outlook.com" />
              </Form.Item>
              <Form.Item name="outlook_official_alias_mode" label="Alias 模式">
                <Input placeholder="official / base / fixed" />
              </Form.Item>
              <Form.Item name="outlook_official_alias_prefix" label="Alias 前缀">
                <Input placeholder="aar" />
              </Form.Item>
              <Form.Item name="outlook_official_target_email" label="固定目标邮箱（可选）">
                <Input placeholder="customalias@outlook.com" />
              </Form.Item>
              <Form.Item name="outlook_official_poll_interval" label="轮询间隔（秒）">
                <InputNumber min={1} style={{ width: '100%' }} />
              </Form.Item>
              <Form.Item name="outlook_official_timeout" label="超时（秒）">
                <InputNumber min={10} style={{ width: '100%' }} />
              </Form.Item>
            </>
          )}
          {mailProvider === 'outlookapi' && (
            <>
              <Form.Item name="outlook_email_base_url" label="API Base URL">
                <Input placeholder="http://127.0.0.1:5000" />
              </Form.Item>
              <Form.Item name="outlook_email_auth_mode" label="认证模式">
                <Input placeholder="auto / external / internal" />
              </Form.Item>
              <Form.Item name="outlook_email_api_key" label="External API Key（可选）">
                <Input.Password placeholder="api_key" />
              </Form.Item>
              <Form.Item name="outlook_email_login_password" label="Internal Login Password（可选）">
                <Input.Password placeholder="password" />
              </Form.Item>
              <Form.Item name="outlook_email_group_id" label="Group ID（可选）">
                <Input placeholder="1" />
              </Form.Item>
              <Form.Item name="outlook_email_address_mode" label="地址策略">
                <Input placeholder="aliases-first / primary-first / aliases-only / primary-only" />
              </Form.Item>
              <Form.Item name="outlook_email_address_pool" label="固定地址池（可选）">
                <Input.TextArea rows={3} placeholder="a@outlook.com,b@outlook.com" />
              </Form.Item>
              <Form.Item name="outlook_email_folder" label="Folder（可选）">
                <Input placeholder="all" />
              </Form.Item>
              <Form.Item name="outlook_email_fetch_top" label="每次抓取条数">
                <InputNumber min={1} max={50} style={{ width: '100%' }} />
              </Form.Item>
              <Form.Item name="outlook_email_disable_used_accounts" label="用后禁用">
                <Input placeholder="true / false" />
              </Form.Item>
              <Form.Item name="outlook_email_disable_used_status" label="禁用状态">
                <Input placeholder="inactive" />
              </Form.Item>
              <Form.Item name="outlook_email_used_addresses_path" label="已用地址 ledger 路径">
                <Input placeholder="/home/.../outlook-email-used-addresses.json" />
              </Form.Item>
              <Form.Item name="outlook_email_poll_interval" label="轮询间隔（秒）">
                <InputNumber min={1} style={{ width: '100%' }} />
              </Form.Item>
              <Form.Item name="outlook_email_timeout" label="超时（秒）">
                <InputNumber min={5} style={{ width: '100%' }} />
              </Form.Item>
              <Form.Item name="outlook_email_proxy" label="代理（可选）">
                <Input placeholder="http://127.0.0.1:7890" />
              </Form.Item>
            </>
          )}
        </Card>

        {captchaSolver === 'yescaptcha' && (
          <Card title="验证码配置" style={{ marginBottom: 16 }}>
            <Form.Item name="yescaptcha_key" label="YesCaptcha Key">
              <Input />
            </Form.Item>
          </Card>
        )}

        {captchaSolver === 'local_solver' && (
          <Card title="本地 Solver 配置" style={{ marginBottom: 16 }}>
            <Form.Item name="solver_url" label="Solver URL">
              <Input />
            </Form.Item>
            <Text type="secondary" style={{ fontSize: 12 }}>
              启动命令: python services/turnstile_solver/start.py --browser_type camoufox --port 8889
            </Text>
          </Card>
        )}

        <Button type="primary" htmlType="submit" block disabled={polling} icon={polling ? <LoadingOutlined /> : <PlayCircleOutlined />}>
          {polling ? '注册中...' : '开始注册'}
        </Button>
      </Form>

      {task && (
        <Card title={
          <Space>
            <span>任务状态</span>
            <Tag color={
              task.status === 'done' ? 'success' :
              task.status === 'failed' ? 'error' : 'processing'
            }>
              {task.status}
            </Tag>
          </Space>
        } style={{ marginTop: 16 }}>
          <Descriptions column={1} size="small">
            <Descriptions.Item label="任务 ID">
              <Text copyable style={{ fontFamily: 'monospace' }}>{task.id}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="进度">{task.progress}</Descriptions.Item>
          </Descriptions>
          {task.success != null && (
            <div style={{ marginTop: 8, color: '#10b981' }}>
              <CheckCircleOutlined /> 成功 {task.success} 个
            </div>
          )}
          {task.errors?.length > 0 && (
            <div style={{ marginTop: 8 }}>
              {task.errors.map((e: string, i: number) => (
                <div key={i} style={{ color: '#ef4444', marginBottom: 4 }}>
                  <CloseCircleOutlined /> {e}
                </div>
              ))}
            </div>
          )}
          {task.error && (
            <div style={{ marginTop: 8, color: '#ef4444' }}>
              <CloseCircleOutlined /> {task.error}
            </div>
          )}
        </Card>
      )}
    </div>
  )
}
